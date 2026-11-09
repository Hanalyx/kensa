package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent"
	"github.com/Hanalyx/kensa/internal/agent/client"
	"github.com/Hanalyx/kensa/internal/agent/ownedexec"
	"github.com/Hanalyx/kensa/internal/agent/wirev1"
	"github.com/Hanalyx/kensa/internal/handler"
)

type recoveryProcess struct {
	cmd        *exec.Cmd
	input      io.WriteCloser
	output     io.ReadCloser
	c          *client.Client
	done       chan error
	reaped     chan struct{}
	stderr     *os.File
	stderrPath string
	ctx        context.Context
}

func recoveryAgent(t *testing.T) *recoveryProcess {
	t.Helper()
	if err := ownedexec.Prepare(); err != nil {
		t.Fatal(err)
	}
	binary := os.Getenv("KENSA_RECOVERY_TEST_BINARY")
	if binary == "" {
		binary = filepath.Join(findRepoRootE2E(t), "bin/kensa")
	}
	if !fileExists(binary) {
		t.Fatal("fresh candidate binary required; run canonical make build")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, binary, "agent", "--stdio")
	return recoveryAgentCommand(ctx, t, cancel, cmd)
}

func recoveryAgentCommand(ctx context.Context, t *testing.T, cancel context.CancelFunc, cmd *exec.Cmd) *recoveryProcess {
	t.Helper()
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrPath := filepath.Join(t.TempDir(), "stderr")
	f, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c, err := client.Open(input, output)
	if err != nil {
		t.Fatal(err)
	}
	p := &recoveryProcess{cmd: cmd, input: input, output: output, c: c, done: make(chan error, 1), reaped: make(chan struct{}), stderr: f, stderrPath: stderrPath, ctx: ctx}
	go func() { p.done <- cmd.Wait(); close(p.reaped) }()
	t.Cleanup(func() {
		_ = input.Close()
		_ = cmd.Process.Kill()
		cancel()
		_ = c.Close()
		select {
		case <-p.reaped:
		case <-time.After(5 * time.Second):
			t.Error("local candidate cleanup did not join")
			return
		}
		_ = ownedexec.Quiesce()
		_ = f.Close()
	})
	if err := c.Handshake(ctx); err != nil {
		t.Fatalf("candidate handshake: %v", err)
	}
	return p
}
func recoveryWait(t *testing.T, p *recoveryProcess, wantSuccess bool) {
	t.Helper()
	select {
	case err := <-p.done:
		if (err == nil) != wantSuccess {
			diag, _ := os.ReadFile(p.stderrPath)
			t.Fatalf("agent exit: %v, success=%v; stderr=%s", err, wantSuccess, diag)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("agent did not join recovery")
	}
}
func recoveryStarted(t *testing.T, p *recoveryProcess, file string) {
	t.Helper()
	end := time.After(5 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(file); err == nil {
			return
		}
		select {
		case err := <-p.done:
			t.Fatalf("agent exited before recovery completed/started: %v", err)
		case <-end:
			t.Fatal("restorer did not start")
		case <-tick.C:
		}
	}
}
func fixtureCommands(t *testing.T, gated bool) (string, string, string, []string) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "fixture")
	absent := filepath.Join(dir, "initially-absent")
	started := filepath.Join(dir, "started")
	release := filepath.Join(dir, "release")
	if err := os.WriteFile(target, []byte("mutated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absent, []byte("created"), 0o600); err != nil {
		t.Fatal(err)
	}
	prefix := ""
	if gated {
		prefix = fmt.Sprintf(`printf started > %q; i=0; while [ ! -f %q ]; do i=$((i+1)); [ "$i" -lt 500 ] || exit 3; sleep 0.01; done; `, started, release)
	}
	return target, started, release, []string{prefix + fmt.Sprintf("printf captured > %q; chmod 0600 %q", target, target), fmt.Sprintf("rm %q", absent)}
}
func assertCaptured(t *testing.T, target string) {
	t.Helper()
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "captured" {
		t.Fatalf("captured bytes not restored: %q %v", data, err)
	}
	s, err := os.Stat(target)
	if err != nil || s.Mode().Perm() != 0o600 {
		t.Fatalf("captured mode not restored: %v %v", s, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(target), "initially-absent")); !os.IsNotExist(err) {
		t.Fatalf("second rollback command lost; created file remains: %v", err)
	}
}

// @spec agent-stdio-subcommand
// @ac AC-09
func TestAgentRecoveryEOFFinishesCompleteSequence(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-09")
	p := recoveryAgent(t)
	target, started, release, commands := fixtureCommands(t, true)
	if _, err := p.c.ArmDeadman(p.ctx, "eof-complete", 60, commands); err != nil {
		t.Fatal(err)
	}
	if err := p.input.Close(); err != nil {
		t.Fatal(err)
	}
	recoveryStarted(t, p, started)
	// The command is deliberately held past the old forced-exit interval.
	select {
	case err := <-p.done:
		t.Fatalf("agent exited with unfinished recovery: %v", err)
	case <-time.After(600 * time.Millisecond):
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	recoveryWait(t, p, true)
	assertCaptured(t, target)
}

// @spec agent-stdio-subcommand
// @ac AC-12
func TestAgentRecoverySIGTERMJoinsBeyondIdleGrace(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-12")
	p := recoveryAgent(t)
	target, started, release, commands := fixtureCommands(t, true)
	if _, err := p.c.ArmDeadman(p.ctx, "signal-complete", 60, commands); err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	recoveryStarted(t, p, started)
	select {
	case err := <-p.done:
		t.Fatalf("500ms fallback abandoned recovery: %v", err)
	case <-time.After(600 * time.Millisecond):
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	recoveryWait(t, p, true)
	assertCaptured(t, target)
}

// @spec agent-stdio-subcommand
// @ac AC-11
func TestAgentRecoveryPreservesTruncatedProtocolError(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-11")
	p := recoveryAgent(t)
	target, _, _, commands := fixtureCommands(t, false)
	if _, err := p.c.ArmDeadman(p.ctx, "protocol-error", 60, commands); err != nil {
		t.Fatal(err)
	}
	if _, err := p.input.Write([]byte{1, 0, 0, 0, 8, 1}); err != nil {
		t.Fatal(err)
	}
	_ = p.input.Close()
	recoveryWait(t, p, false)
	assertCaptured(t, target)
	diag, _ := os.ReadFile(p.stderrPath)
	if !strings.Contains(string(diag), "unexpected EOF") {
		t.Fatalf("original protocol failure erased: %s", diag)
	}
}

// @spec agent-stdio-subcommand
// @ac AC-11
func TestAgentRecoveryBrokenOutputDoesNotBypassDrain(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-11")
	p := recoveryAgent(t)
	target, _, _, commands := fixtureCommands(t, false)
	if _, err := p.c.ArmDeadman(p.ctx, "output-error", 60, commands); err != nil {
		t.Fatal(err)
	}
	_ = p.output.Close()
	payload, err := proto.Marshal(&wirev1.Request{SchemaVersion: 1, CorrelationId: 12345, Payload: &wirev1.Request_Heartbeat{Heartbeat: &wirev1.HeartbeatRequest{}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Write(p.input, agent.FramePayload, payload, nil); err != nil {
		t.Fatal(err)
	}
	recoveryWait(t, p, false)
	assertCaptured(t, target)
}

// @spec agent-stdio-subcommand
// @ac AC-11
func TestAgentRecoveryOrdinaryCommandErrorStillRunsNext(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-11")
	p := recoveryAgent(t)
	target, _, _, commands := fixtureCommands(t, false)
	commands = append([]string{"exit 9"}, commands...)
	if _, err := p.c.ArmDeadman(p.ctx, "command-error", 60, commands); err != nil {
		t.Fatal(err)
	}
	_ = p.input.Close()
	recoveryWait(t, p, false)
	assertCaptured(t, target)
}

// @spec agent-stdio-subcommand
// @ac AC-10
func TestAgentRecoveryPreShutdownCancellationSuppressesRecovery(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-10")
	p := recoveryAgent(t)
	target, _, _, commands := fixtureCommands(t, false)
	if _, err := p.c.ArmDeadman(p.ctx, "cancel-pending", 60, commands); err != nil {
		t.Fatal(err)
	}
	active, err := p.c.CancelDeadman(p.ctx, "cancel-pending")
	if err != nil || !active {
		t.Fatalf("cancel: %v %v", active, err)
	}
	active, err = p.c.CancelDeadman(p.ctx, "cancel-pending")
	if err != nil || active {
		t.Fatalf("repeat cancel: %v %v", active, err)
	}
	_ = p.input.Close()
	recoveryWait(t, p, true)
	if data, err := os.ReadFile(target); err != nil || string(data) != "mutated" {
		t.Fatalf("canceled recovery fired: %q %v", data, err)
	}
}

// The subprocess registers a controlled test handler so Apply occupies the
// actual synchronous dispatcher while stdin closes. Its writes are local test
// fixtures, not a claim about any shipped handler's restoration capability.
type busyPipeHandler struct{ dir string }

func (h *busyPipeHandler) Name() string     { return "busy_pipe_fixture" }
func (h *busyPipeHandler) Capturable() bool { return false }
func (h *busyPipeHandler) Apply(ctx context.Context, _ api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	if err := os.WriteFile(filepath.Join(h.dir, "admitted"), nil, 0600); err != nil {
		return nil, err
	}
	<-ctx.Done()
	if err := os.WriteFile(filepath.Join(h.dir, "stop-requested"), nil, 0600); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(h.dir, "release")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("fixture mutation not released")
		}
		time.Sleep(5 * time.Millisecond)
	}
	err := os.WriteFile(filepath.Join(h.dir, "fixture"), []byte("last admitted write"), 0600)
	return &api.StepResult{Success: err == nil}, err
}
func (h *busyPipeHandler) Rollback(context.Context, api.Transport, *api.PreState) (*api.RollbackResult, error) {
	return nil, fmt.Errorf("fixture supports Apply only")
}
func TestAgentRecoveryBusyMutationFixture(t *testing.T) {
	dir := os.Getenv("KENSA_BUSY_MUTATION_FIXTURE")
	if dir == "" {
		return
	}
	handler.Register(&busyPipeHandler{dir: dir})
	if err := runAgent([]string{"--stdio"}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	os.Exit(0)
}

// @spec agent-stdio-subcommand
// @ac AC-09
func TestAgentRecoveryEOFWhileMutationBusy(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-09")
	if err := ownedexec.Prepare(); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target, _, release, commands := fixtureCommands(t, false)
	dir := filepath.Dir(target)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestAgentRecoveryBusyMutationFixture$")
	cmd.Env = append(os.Environ(), "KENSA_BUSY_MUTATION_FIXTURE="+dir)
	p := recoveryAgentCommand(ctx, t, cancel, cmd)
	if _, err := p.c.ArmDeadman(p.ctx, "busy-eof", 60, commands); err != nil {
		t.Fatal(err)
	}
	payload, err := proto.Marshal(&wirev1.Request{SchemaVersion: 1, CorrelationId: 23456, Payload: &wirev1.Request_Apply{Apply: &wirev1.ApplyRequest{Mechanism: "busy_pipe_fixture"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Write(p.input, agent.FramePayload, payload, nil); err != nil {
		t.Fatal(err)
	}
	recoveryStarted(t, p, filepath.Join(dir, "admitted"))
	if err := p.input.Close(); err != nil {
		t.Fatal(err)
	}
	recoveryStarted(t, p, filepath.Join(dir, "stop-requested"))
	if data, err := os.ReadFile(target); err != nil || string(data) != "mutated" {
		t.Fatalf("recovery overtook active mutation: %q %v", data, err)
	}
	if err := os.WriteFile(release, nil, 0600); err != nil {
		t.Fatal(err)
	}
	recoveryWait(t, p, true)
	assertCaptured(t, target)
}
