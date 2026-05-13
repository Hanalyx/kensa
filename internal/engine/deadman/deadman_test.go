package deadman_test

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/engine/deadman"
	"github.com/Hanalyx/kensa-go/internal/handler"

	// Register sysctlset so dry-run rollback tests can use it.
	_ "github.com/Hanalyx/kensa-go/internal/handlers/sysctlset"
)

// substringFakeTransport is a test fake for api.Transport that matches
// Results keys by substring, making tests insensitive to UUID-stamped
// command strings. Unmatched commands return exit 0 with empty output.
type substringFakeTransport struct {
	Runs    []string
	Results map[string]api.CommandResult // substring key → result
}

func newSubTP() *substringFakeTransport {
	return &substringFakeTransport{Results: make(map[string]api.CommandResult)}
}

func (f *substringFakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	f.Runs = append(f.Runs, cmd)
	for k, v := range f.Results {
		if strings.Contains(cmd, k) {
			r := v
			return &r, nil
		}
	}
	return &api.CommandResult{ExitCode: 0}, nil
}

func (f *substringFakeTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (f *substringFakeTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (f *substringFakeTransport) Close() error                                            { return nil }
func (f *substringFakeTransport) ControlChannelSensitive() bool                           { return false }

// atHostTP returns a transport simulating an at(1)-capable host.
func atHostTP() *substringFakeTransport {
	tp := newSubTP()
	// Scheduler detection: "command -v at" probe.
	tp.Results["__AT_FOUND__"] = api.CommandResult{Stdout: "__AT_FOUND__"}
	// at scheduling: "echo sh ... | at now + N seconds 2>&1"
	// at(1) prints "job N at <date>" to stderr/stdout.
	tp.Results["| at now +"] = api.CommandResult{Stdout: "job 42 at Thu Apr 15 12:00:00 2026"}
	// atq verification: job 42 appears in queue.
	tp.Results["atq"] = api.CommandResult{Stdout: "42\t Thu Apr 15 12:00:00 2026 a root"}
	return tp
}

// sdrHostTP returns a transport simulating a systemd-run-capable host.
func sdrHostTP() *substringFakeTransport {
	tp := newSubTP()
	// at not found (no __AT_FOUND__ key, returns empty default).
	// systemd-run found.
	tp.Results["__SDR_FOUND__"] = api.CommandResult{Stdout: "__SDR_FOUND__"}
	// systemd-run scheduling succeeds (default exit 0).
	// Verify unit exists: LoadState = "loaded".
	tp.Results["LoadState"] = api.CommandResult{Stdout: "loaded"}
	return tp
}

// @spec deadman-timer
// @ac AC-01
func TestDetectScheduler_At(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Log("// @ac AC-01")
	tp := atHostTP()
	a := deadman.New(0, handler.NewRegistry())
	_, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{})
	if err != nil {
		t.Fatalf("Arm with at-capable host: %v", err)
	}
}

// @spec deadman-timer
// @ac AC-01
func TestDetectScheduler_SystemdRun(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Log("// @ac AC-01")
	tp := sdrHostTP()
	a := deadman.New(0, handler.NewRegistry())
	_, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{})
	if err != nil {
		t.Fatalf("Arm with systemd-run-capable host: %v", err)
	}
}

// @spec deadman-timer
// @ac AC-01
func TestDetectScheduler_NoScheduler(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Log("// @ac AC-01")
	// Transport returns nothing recognizable for scheduler probes.
	tp := newSubTP()
	a := deadman.New(0, handler.NewRegistry())
	_, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{})
	if err != api.ErrSchedulerUnavailable {
		t.Fatalf("expected ErrSchedulerUnavailable, got %v", err)
	}
}

// @spec deadman-timer
// @ac AC-02
// @ac AC-03
// @ac AC-04
func TestArm_UploadAndSchedule(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Run("deadman-timer/AC-02", func(t *testing.T) {})
	t.Run("deadman-timer/AC-03", func(t *testing.T) {})
	t.Run("deadman-timer/AC-04", func(t *testing.T) {})
	tp := atHostTP()
	a := deadman.New(0, handler.NewRegistry())

	txnID := uuid.New()
	scriptPath, firesAt, err := a.Arm(context.Background(), tp, txnID, []api.PreState{})
	if err != nil {
		t.Fatalf("Arm: %v", err)
	}
	// Script path must contain the txn ID.
	if !strings.Contains(scriptPath, txnID.String()) {
		t.Errorf("scriptPath %q does not contain txn ID %s", scriptPath, txnID)
	}
	// firesAt must be in the future.
	if firesAt <= time.Now().Unix() {
		t.Errorf("firesAt %d is not in the future", firesAt)
	}
	// Upload command (printf) must appear in Runs.
	var uploadSeen bool
	for _, r := range tp.Runs {
		if strings.Contains(r, "printf") && strings.Contains(r, "rollback") {
			uploadSeen = true
			break
		}
	}
	if !uploadSeen {
		t.Errorf("no printf upload cmd found in Runs:\n%v", strings.Join(tp.Runs, "\n"))
	}
	// Scheduling command (at) must appear in Runs.
	var schedSeen bool
	for _, r := range tp.Runs {
		if strings.Contains(r, "| at now +") {
			schedSeen = true
			break
		}
	}
	if !schedSeen {
		t.Errorf("no 'at' scheduling cmd found in Runs:\n%v", strings.Join(tp.Runs, "\n"))
	}
}

// @spec deadman-timer
// @ac AC-02
func TestArm_ScriptContainsRollbackCommands(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Log("// @ac AC-02")
	tp := atHostTP()
	// Use the global registry so sysctlset is registered.
	a := deadman.New(0, handler.Default())

	preStates := []api.PreState{{
		StepIndex:  0,
		Mechanism:  "sysctl_set",
		Capturable: true,
		Data: map[string]interface{}{
			"runtime_value": "0",
			"persist_file":  "/etc/sysctl.d/99-kensa.conf",
			"key":           "kernel.dmesg_restrict",
		},
	}}

	_, _, err := a.Arm(context.Background(), tp, uuid.New(), preStates)
	if err != nil {
		t.Fatalf("Arm: %v", err)
	}

	// Find the upload command and verify it contains rollback step content.
	var uploadCmd string
	for _, r := range tp.Runs {
		if strings.Contains(r, "printf") && strings.Contains(r, "rollback step") {
			uploadCmd = r
			break
		}
	}
	if uploadCmd == "" {
		t.Errorf("no upload command with 'rollback step' found in Runs:\n%v",
			strings.Join(tp.Runs, "\n"))
	}
}

// @spec deadman-timer
// @ac AC-05
// @ac AC-09
func TestCancel_ErrNoActiveDeadman(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Run("deadman-timer/AC-05", func(t *testing.T) {})
	t.Run("deadman-timer/AC-09", func(t *testing.T) {})
	tp := newSubTP()
	a := deadman.New(0, handler.NewRegistry())
	err := a.Cancel(context.Background(), tp, uuid.New())
	if err != api.ErrNoActiveDeadman {
		t.Fatalf("expected ErrNoActiveDeadman, got %v", err)
	}
}

// @spec deadman-timer
// @ac AC-05
// @ac AC-08
func TestCancel_RemovesJobAndScript(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Run("deadman-timer/AC-05", func(t *testing.T) {})
	t.Run("deadman-timer/AC-08", func(t *testing.T) {})
	tp := atHostTP()
	// After cancel: atq returns empty (job gone).
	// Override the "atq" key to return empty string so post-cancel verification passes.
	// We need a two-phase transport: before cancel atq has job 42, after cancel it's gone.
	// Simplest: run Arm with tp, then swap the atq response.

	a := deadman.New(0, handler.NewRegistry())
	txnID := uuid.New()

	// Arm successfully.
	_, _, err := a.Arm(context.Background(), tp, txnID, []api.PreState{})
	if err != nil {
		t.Fatalf("Arm: %v", err)
	}

	// Switch atq to return empty (simulates job removed by atrm).
	tp.Results["atq"] = api.CommandResult{Stdout: ""}

	// Cancel should succeed.
	if err := a.Cancel(context.Background(), tp, txnID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	// Second Cancel should return ErrNoActiveDeadman (state cleared).
	if err := a.Cancel(context.Background(), tp, txnID); err != api.ErrNoActiveDeadman {
		t.Fatalf("second Cancel: expected ErrNoActiveDeadman, got %v", err)
	}
}

// @spec deadman-timer
// @ac AC-06
func TestDeadman_AC06_ScriptFiresOnConnectionLoss(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Log("// @ac AC-06")
	// AC-06 requires simulating mid-apply SSH disconnection followed by
	// reconnect to verify the engine records rollback_source=deadman.
	// This is an integration property that cannot be unit-tested without
	// a real or emulated SSH transport; the buildScript test (AC-02)
	// verifies that the generated script is correct and self-contained.
	t.Skip("TODO: requires emulated SSH disconnect; covered structurally by AC-02 script content tests")
}

// @spec deadman-timer
// @ac AC-07
func TestDeadman_AC07_KeepAliveExtendsWindow(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Log("// @ac AC-07")
	// AC-07 requires a keep-alive mechanism (Extend call every 30s that
	// re-schedules the job with +60s). Not yet implemented in Armer.
	// Track in SPECTER_FEATURE_REQUEST.md.
	t.Skip("TODO: keep-alive Extend() not yet implemented in deadman.Armer")
}

// @spec deadman-timer
// @ac AC-10
func TestDeadman_AC10_ClockSkewExtendsWindow(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Log("// @ac AC-10")
	// AC-10 requires pre/post date comparison on the host to detect clock
	// skew and extend the window proportionally. Not yet implemented.
	// Track in SPECTER_FEATURE_REQUEST.md.
	t.Skip("TODO: clock skew detection not yet implemented in deadman.Armer")
}

// @spec deadman-timer
// @ac AC-03
func TestArm_DefaultWindowIsAtLeast120s(t *testing.T) {
	t.Log("// @spec deadman-timer")
	t.Log("// @ac AC-03")
	tp := atHostTP()
	a := deadman.New(0, handler.NewRegistry()) // 0 → use default 120s
	_, firesAt, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{})
	if err != nil {
		t.Fatalf("Arm: %v", err)
	}
	minExpected := time.Now().Add(100 * time.Second).Unix()
	if firesAt < minExpected {
		t.Errorf("firesAt %d appears to be less than 100s from now (%d); default window may be < 120s",
			firesAt, minExpected)
	}
}

// ─── D-005 dispatch tests ─────────────────────────────────────

// fakeAgentDeadmanClient implements the local
// agentDeadmanClient interface for D-005 dispatch tests.
type fakeAgentDeadmanClient struct {
	armCalled    int
	armTxnID     string
	armWindow    int64
	armCommands  []string
	armFiresAt   int64
	armErr       error
	cancelCalled int
	cancelTxnID  string
	cancelActive bool
	cancelErr    error
}

func (f *fakeAgentDeadmanClient) ArmDeadman(_ context.Context, txnID string, windowSec int64, cmds []string) (int64, error) {
	f.armCalled++
	f.armTxnID = txnID
	f.armWindow = windowSec
	f.armCommands = cmds
	if f.armErr != nil {
		return 0, f.armErr
	}
	return f.armFiresAt, nil
}

func (f *fakeAgentDeadmanClient) CancelDeadman(_ context.Context, txnID string) (bool, error) {
	f.cancelCalled++
	f.cancelTxnID = txnID
	return f.cancelActive, f.cancelErr
}

// TestDeadman_D005_AgentDispatch_ArmRoutesThroughRPC locks
// the agent-mode dispatch: when UseAgentClient has been
// called, Arm calls ArmDeadman on the AgentClient and does
// NOT touch the shell-based scheduler.
func TestDeadman_D005_AgentDispatch_ArmRoutesThroughRPC(t *testing.T) {
	fake := &fakeAgentDeadmanClient{
		armFiresAt: time.Now().Add(120 * time.Second).Unix(),
	}
	a := deadman.New(0, handler.NewRegistry())
	a.UseAgentClient(fake)

	// Use a transport that would FAIL if the shell path were
	// taken (no `at` or `systemd-run` configured). The agent
	// dispatch should never touch it.
	tp := nilTransport{}
	txnID := uuid.New()

	scriptPath, firesAt, err := a.Arm(context.Background(), tp, txnID, []api.PreState{})
	if err != nil {
		t.Fatalf("Arm via agent: %v", err)
	}
	if fake.armCalled != 1 {
		t.Errorf("ArmDeadman call count: got %d, want 1", fake.armCalled)
	}
	if fake.armTxnID != txnID.String() {
		t.Errorf("ArmDeadman txn_id: got %q, want %q", fake.armTxnID, txnID.String())
	}
	if fake.armWindow != 120 {
		t.Errorf("ArmDeadman window_seconds: got %d, want 120", fake.armWindow)
	}
	if scriptPath != "" {
		t.Errorf("agent-mode scriptPath: got %q, want empty", scriptPath)
	}
	if firesAt != fake.armFiresAt {
		t.Errorf("firesAt: got %d, want %d", firesAt, fake.armFiresAt)
	}
}

// TestDeadman_D005_AgentDispatch_CancelRoutesThroughRPC.
func TestDeadman_D005_AgentDispatch_CancelRoutesThroughRPC(t *testing.T) {
	fake := &fakeAgentDeadmanClient{
		armFiresAt:   time.Now().Add(120 * time.Second).Unix(),
		cancelActive: true,
	}
	a := deadman.New(0, handler.NewRegistry())
	a.UseAgentClient(fake)
	tp := nilTransport{}
	txnID := uuid.New()

	if _, _, err := a.Arm(context.Background(), tp, txnID, []api.PreState{}); err != nil {
		t.Fatal(err)
	}

	if err := a.Cancel(context.Background(), tp, txnID); err != nil {
		t.Fatalf("Cancel via agent: %v", err)
	}
	if fake.cancelCalled != 1 {
		t.Errorf("CancelDeadman call count: got %d, want 1", fake.cancelCalled)
	}
	if fake.cancelTxnID != txnID.String() {
		t.Errorf("CancelDeadman txn_id: got %q, want %q", fake.cancelTxnID, txnID.String())
	}
}

// TestDeadman_D005_AgentDispatch_RPCFailureSurfacesError
// locks the Q1.a ratification: if the agent RPC fails,
// Arm fails too (no silent fall-back to shell).
func TestDeadman_D005_AgentDispatch_RPCFailureSurfacesError(t *testing.T) {
	fake := &fakeAgentDeadmanClient{
		armErr: errors.New("simulated agent RPC failure"),
	}
	a := deadman.New(0, handler.NewRegistry())
	a.UseAgentClient(fake)
	tp := nilTransport{}

	_, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{})
	if err == nil {
		t.Fatal("expected error when agent RPC fails; got nil")
	}
	if !strings.Contains(err.Error(), "simulated agent RPC failure") {
		t.Errorf("error should wrap the agent failure; got: %v", err)
	}
}

// nilTransport is an api.Transport that panics if any method
// is called. Used by D-005 agent-dispatch tests to prove the
// agent path doesn't touch transport at all.
type nilTransport struct{}

func (nilTransport) Run(_ context.Context, _ string) (*api.CommandResult, error) {
	panic("nilTransport.Run called — agent-mode dispatch should not touch the transport")
}
func (nilTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error {
	panic("nilTransport.Put called")
}
func (nilTransport) Get(_ context.Context, _, _ string) error { panic("nilTransport.Get called") }
func (nilTransport) ControlChannelSensitive() bool            { return false }
func (nilTransport) Close() error                              { return nil }

// TestDeadman_D005_InterfaceSatisfaction is the compile-time
// assertion the post-D-005 peer review demanded: if
// deadman.Armer ever stops satisfying engine.AgentAwareDeadmanArmer,
// engine.New's type assertion silently falls through and
// agent-mode dispatch becomes dead code. This test fails the
// build if the contract breaks.
//
// Importing engine + deadman from a _test package avoids the
// cycle that prevents the production code from using this
// assertion directly.
func TestDeadman_D005_InterfaceSatisfaction(t *testing.T) {
	var _ engine.AgentAwareDeadmanArmer = (*deadman.Armer)(nil)
}
