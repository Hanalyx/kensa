package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent"
	"github.com/Hanalyx/kensa/internal/agent/wirev1"
	"github.com/Hanalyx/kensa/internal/handler"
)

type capturePipeHandler struct{ dir string }

func (h *capturePipeHandler) Name() string     { return "capture_pipe_fixture" }
func (h *capturePipeHandler) Capturable() bool { return true }
func (h *capturePipeHandler) Apply(context.Context, api.Transport, api.Params, *api.PreState) (*api.StepResult, error) {
	return nil, errors.New("Capture-only fixture")
}
func (h *capturePipeHandler) Rollback(context.Context, api.Transport, *api.PreState) (*api.RollbackResult, error) {
	return nil, errors.New("Capture-only fixture")
}
func (h *capturePipeHandler) Capture(ctx context.Context, _ api.Transport, _ api.Params) (*api.PreState, error) {
	// Real native execution with the unmarked, naturally completing context.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("printf started > %q; i=0; while [ ! -f %q ]; do i=$((i+1)); [ \"$i\" -lt 500 ] || exit 3; sleep 0.01; done; printf native-output", filepath.Join(h.dir, "capture-started"), filepath.Join(h.dir, "capture-release")))
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := os.WriteFile(filepath.Join(h.dir, "capture-joined"), output, 0600); err != nil {
		return nil, err
	}
	return &api.PreState{Mechanism: h.Name(), Capturable: true, Data: map[string]any{"output": string(output)}}, nil
}
func TestAgentCaptureProcessFixture(t *testing.T) {
	dir := os.Getenv("KENSA_CAPTURE_PIPE_FIXTURE")
	if dir == "" {
		return
	}
	handler.Register(&capturePipeHandler{dir: dir})
	if err := runAgent([]string{"--stdio"}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	os.Exit(0)
}

// @spec agent-stdio-subcommand
// @ac AC-09
func TestAgentEOFWaitsForNaturalCaptureBeyondIdleGrace(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-09")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target, _, _, commands := fixtureCommands(t, false)
	dir := filepath.Dir(target)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestAgentCaptureProcessFixture$")
	cmd.Env = append(os.Environ(), "KENSA_CAPTURE_PIPE_FIXTURE="+dir)
	p := recoveryAgentCommand(ctx, t, cancel, cmd)
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(dir, "capture-release"), nil, 0600) })
	if _, err := p.c.ArmDeadman(p.ctx, "capture-eof", 60, commands); err != nil {
		t.Fatal(err)
	}
	request, err := proto.Marshal(&wirev1.Request{SchemaVersion: 1, CorrelationId: 34567, Payload: &wirev1.Request_Capture{Capture: &wirev1.CaptureRequest{Mechanism: "capture_pipe_fixture"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Write(p.input, agent.FramePayload, request, nil); err != nil {
		t.Fatal(err)
	}
	recoveryStarted(t, p, filepath.Join(dir, "capture-started"))
	if err := p.input.Close(); err != nil {
		t.Fatal(err)
	}
	// The existing busy-input observer must see EOF while Capture owns the loop.
	deadline := time.Now().Add(3 * time.Second)
	for {
		diagnostic, err := os.ReadFile(p.stderrPath)
		if err != nil {
			t.Fatal(err)
		}
		if contains := string(diagnostic); strings.Contains(contains, "shutdown waiting for natural Capture completion") {
			break
		}
		select {
		case err := <-p.done:
			t.Fatalf("agent abandoned native Capture: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("EOF did not close admission during busy Capture: %s", diagnostic)
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-p.done:
		t.Fatalf("500ms idle exit abandoned Capture: %v", err)
	case <-time.After(600 * time.Millisecond):
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "mutated" {
		t.Fatalf("recovery overtook Capture: %q %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "capture-release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	recoveryWait(t, p, true)
	if data, err := os.ReadFile(filepath.Join(dir, "capture-joined")); err != nil || string(data) != "native-output" {
		t.Fatalf("native Capture did not join naturally: %q %v", data, err)
	}
	assertCaptured(t, target)
}
