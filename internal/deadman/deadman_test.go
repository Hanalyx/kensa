package deadman_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/deadman"
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
	// Transport returns nothing recognizable for scheduler probes.
	tp := newSubTP()
	a := deadman.New(0, handler.NewRegistry())
	_, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{})
	if err != api.ErrSchedulerUnavailable {
		t.Fatalf("expected ErrSchedulerUnavailable, got %v", err)
	}
}

// @spec deadman-timer
// @ac AC-02 AC-03 AC-04
func TestArm_UploadAndSchedule(t *testing.T) {
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
// @ac AC-05 AC-09
func TestCancel_ErrNoActiveDeadman(t *testing.T) {
	tp := newSubTP()
	a := deadman.New(0, handler.NewRegistry())
	err := a.Cancel(context.Background(), tp, uuid.New())
	if err != api.ErrNoActiveDeadman {
		t.Fatalf("expected ErrNoActiveDeadman, got %v", err)
	}
}

// @spec deadman-timer
// @ac AC-05 AC-08
func TestCancel_RemovesJobAndScript(t *testing.T) {
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
// @ac AC-03
func TestArm_DefaultWindowIsAtLeast120s(t *testing.T) {
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
