//go:build linux

package deadman_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/deadman"
	"github.com/Hanalyx/kensa/internal/agent/ownedexec"
	"github.com/Hanalyx/kensa/internal/agent/server"
	"github.com/Hanalyx/kensa/internal/agent/wirev1"
	"github.com/Hanalyx/kensa/internal/handler"
)

type uncertainCapture struct{ mode string }

func (h *uncertainCapture) Name() string     { return "uncertain_native_capture" }
func (h *uncertainCapture) Capturable() bool { return true }
func (h *uncertainCapture) Apply(context.Context, api.Transport, api.Params, *api.PreState) (*api.StepResult, error) {
	return nil, errors.New("Capture-only fixture")
}
func (h *uncertainCapture) Rollback(context.Context, api.Transport, *api.PreState) (*api.RollbackResult, error) {
	return nil, errors.New("Capture-only fixture")
}
func (h *uncertainCapture) Capture(ctx context.Context, _ api.Transport, _ api.Params) (*api.PreState, error) {
	if h.mode == "ordinary" {
		return nil, errors.New("ordinary Capture validation failure")
	}
	child := exec.Command("/bin/sh", "-c", "exit 0")
	if err := child.Start(); err != nil {
		return nil, err
	}
	// Deliberately consume this fixture child's status before its original Wait,
	// reproducing the real native error without leaving any live child behind.
	if _, err := unix.Wait4(child.Process.Pid, nil, 0, nil); err != nil {
		return nil, err
	}
	err := child.Wait()
	if !errors.Is(err, unix.ECHILD) {
		return nil, fmt.Errorf("fixture failed to produce native wait error: %v", err)
	}
	if h.mode == "swallowed" {
		_ = ownedexec.ObserveNativeWait(ctx, child, err)
		return &api.PreState{Mechanism: h.Name(), Capturable: true, Data: map[string]any{"handler_swallowed_wait_error": true}}, nil
	}
	return nil, fmt.Errorf("native Capture wait: %w", err)
}

// @spec agent-stdio-subcommand
// @ac AC-09
func TestCaptureWaitUncertaintyStaysOwned(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-09")
	for _, mode := range []string{"raw", "swallowed", "ordinary"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaptureWaitOutcomeFixture$", "-test.v")
			child.Env = append(os.Environ(), "KENSA_CAPTURE_WAIT_OUTCOME="+mode)
			output, err := child.CombinedOutput()
			if err != nil {
				t.Fatalf("isolated ownership assertion: %v\n%s", err, output)
			}
			t.Logf("isolated %s control:\n%s", mode, output)
		})
	}
}

// This assertion subprocess ends with fixture-only watcher goroutines pending
// in uncertainty cases. Its exit is not a product clean-exit claim. All native
// children were actually reaped above before those assertions are made.
func TestCaptureWaitOutcomeFixture(t *testing.T) {
	mode := os.Getenv("KENSA_CAPTURE_WAIT_OUTCOME")
	if mode == "" {
		return
	}
	a := deadman.New()
	h := &uncertainCapture{mode: mode}
	handler.Register(h)
	target := filepath.Join(t.TempDir(), "must-wait")
	if _, err := a.ArmDeadman("native-outcome", time.Minute, []string{fmt.Sprintf("printf restored > %q", target)}); err != nil {
		t.Fatal(err)
	}
	response := server.HandlerFor(a)(&wirev1.Request{SchemaVersion: 1, CorrelationId: 1, Payload: &wirev1.Request_Capture{Capture: &wirev1.CaptureRequest{Mechanism: h.Name()}}})
	if response.GetError() == nil {
		t.Fatalf("uncertain or failed Capture incorrectly returned success: %v", response)
	}

	if mode != "ordinary" && !a.Handling() {
		t.Fatal("uncertain native completion released Capture token")
	}
	if mode == "ordinary" && a.Handling() {
		t.Fatal("ordinary Capture error incorrectly retained ownership")
	}
	a.StartShutdown(nil)
	drain := make(chan error, 1)
	go func() { drain <- a.Drain() }()
	if mode == "ordinary" {
		select {
		case err := <-drain:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ordinary Capture failure blocked settled recovery")
		}
		if data, err := os.ReadFile(target); err != nil || string(data) != "restored" {
			t.Fatalf("ordinary failure blocked restoration: %q %v", data, err)
		}
		return
	}
	waitClaim(t, a)
	select {
	case err := <-drain:
		t.Fatalf("native wait uncertainty permitted idle completion: %v", err)
	case <-time.After(600 * time.Millisecond):
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("recovery overtook unknown native completion: %v", err)
	}
	if !a.Handling() {
		t.Fatal("uncertainty disappeared after shutdown")
	}
	t.Log("actual native ECHILD remains owned; recovery and idle completion refused")
}
