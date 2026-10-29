//go:build linux

package deadman_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/deadman"
	"github.com/Hanalyx/kensa/internal/agent/server"
	"github.com/Hanalyx/kensa/internal/agent/systemd"
	"github.com/Hanalyx/kensa/internal/agent/wirev1"
	"github.com/Hanalyx/kensa/internal/handler"
)

type captureWaitReport struct {
	code   int
	output string
	err    error
}
type nativeCapture struct {
	name, dir, variant      string
	code                    int
	entered, ready, release chan struct{}
	once                    sync.Once
	calls                   atomic.Int32
	original                context.Context
	report                  chan captureWaitReport
	result                  captureWaitReport
	pid                     int
}

func (h *nativeCapture) publish(v captureWaitReport) { h.result = v; h.report <- v }

func (h *nativeCapture) Name() string     { return h.name }
func (h *nativeCapture) Capturable() bool { return true }
func (h *nativeCapture) Apply(context.Context, api.Transport, api.Params, *api.PreState) (*api.StepResult, error) {
	return nil, errors.New("Capture-only fixture")
}
func (h *nativeCapture) Rollback(context.Context, api.Transport, *api.PreState) (*api.RollbackResult, error) {
	return nil, errors.New("Capture-only fixture")
}
func (h *nativeCapture) releaseWork() {
	h.once.Do(func() { close(h.release); _ = os.WriteFile(filepath.Join(h.dir, "release"), nil, 0600) })
}
func (h *nativeCapture) Capture(ctx context.Context, _ api.Transport, _ api.Params) (*api.PreState, error) {
	if h.calls.Add(1) != 1 {
		return nil, errors.New("unexpected later Capture admission")
	}
	h.original = ctx
	close(h.entered)
	if h.variant == "helper" {
		// NewWithPath retains the actual runner/NDJSON parser. This executable
		// never calls D-Bus or systemctl; it exercises native process ownership.
		result, err := systemd.NewWithPath(filepath.Join(h.dir, "helper")).UnitState(ctx, "fixture.service")
		output := ""
		if result != nil && result.UnitState != nil {
			output = result.UnitState.ActiveState
		}
		h.publish(captureWaitReport{output: output, err: err})
		if err != nil {
			return nil, err
		}
		return &api.PreState{Mechanism: h.name, Capturable: true, Data: map[string]any{"native_output": output}}, nil
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("printf native-output; exit %d", h.code))
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Start(); err != nil {
		h.publish(captureWaitReport{err: err})
		return nil, err
	}
	h.pid = cmd.Process.Pid
	// A real kernel zombie is deliberately left for its original Wait owner.
	// Capture admission, not the child exit alone, must exclude the reaper.
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", h.pid))
		if err != nil {
			h.releaseWork()
			_ = cmd.Wait()
			h.publish(captureWaitReport{err: err})
			return nil, err
		}
		fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))
		if fields[0] == "Z" {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			err = errors.New("native child did not exit")
			h.publish(captureWaitReport{err: err})
			return nil, err
		}
		time.Sleep(time.Millisecond)
	}
	close(h.ready)
	<-h.release
	err := cmd.Wait()
	code := 0
	if err != nil {
		var exited *exec.ExitError
		if errors.As(err, &exited) {
			code = exited.ExitCode()
			err = nil
		}
	}
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	h.publish(captureWaitReport{code: code, output: output.String(), err: err})
	if err != nil {
		return nil, err
	}
	return &api.PreState{Mechanism: h.name, Capturable: true, Data: map[string]any{"native_exit": code, "native_output": output.String()}}, nil
}
func waitCaptureEvent(t *testing.T, event <-chan struct{}, done <-chan *wirev1.Response, label string) {
	t.Helper()
	select {
	case <-event:
	case result := <-done:
		t.Fatalf("Capture ended before %s: %v", label, result)
	case <-time.After(5 * time.Second):
		t.Fatalf("Capture %s not observed", label)
	}
}
func waitClaim(t *testing.T, a *deadman.Armer) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		claimed, changed := a.RecoveryClaimForTest()
		if claimed {
			return
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatal("actual recovery claim not observed")
		}
	}
}

// @spec agent-stdio-subcommand
// @ac AC-09
func TestCaptureNativeWaitOwnsCompletionBeforeRecovery(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-09")
	cases := []struct {
		name, variant, trigger string
		code                   int
	}{
		{"zombie-zero-shutdown", "zombie", "shutdown", 0},
		{"zombie-seven-shutdown", "zombie", "shutdown", 7},
		{"zombie-seven-timer", "zombie", "timer", 7},
		{"live-helper-shutdown", "helper", "shutdown", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "fixture")
			absent := filepath.Join(dir, "initially-absent")
			count := filepath.Join(dir, "executions")
			if err := os.WriteFile(target, []byte("mutated"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(absent, []byte("created"), 0600); err != nil {
				t.Fatal(err)
			}
			h := &nativeCapture{name: "native_capture_" + strings.ReplaceAll(tc.name, "-", "_"), dir: dir, variant: tc.variant, code: tc.code, entered: make(chan struct{}), ready: make(chan struct{}), release: make(chan struct{}), report: make(chan captureWaitReport, 1)}
			if tc.variant == "helper" {
				script := fmt.Sprintf("#!/bin/sh\nprintf started > %q\ni=0\nwhile [ ! -f %q ]; do i=$((i+1)); [ \"$i\" -lt 500 ] || exit 3; sleep 0.01; done\nprintf '%%s\\n' '%s'\n", filepath.Join(dir, "helper-started"), filepath.Join(dir, "release"), `{"schema_version":1,"helper_version":"dev","op":"unit-state","unit":"fixture.service","success":true,"unit_state":{"active_state":"fixture-active"}}`)
				if err := os.WriteFile(filepath.Join(dir, "helper"), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			handler.Register(h)
			a := deadman.New()
			dispatch := server.HandlerFor(a)
			request := &wirev1.Request{SchemaVersion: 1, CorrelationId: 20, Payload: &wirev1.Request_Capture{Capture: &wirev1.CaptureRequest{Mechanism: h.name}}}
			captureDone := make(chan *wirev1.Response, 1)
			captureFinished := make(chan struct{})
			go func() { captureDone <- dispatch(request); close(captureFinished) }()
			t.Cleanup(func() {
				h.releaseWork()
				select {
				case <-captureFinished:
					t.Logf("original Capture wait outcome: code=%d output=%q err=%v", h.result.code, h.result.output, h.result.err)
				case <-time.After(5 * time.Second):
					t.Error("original Capture caller did not join")
				}
				a.StartShutdown(nil)
				done := make(chan error, 1)
				go func() { done <- a.Drain() }()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("fixture lifecycle did not join")
				}
			})
			waitCaptureEvent(t, h.entered, captureDone, "admission")
			if tc.variant == "helper" {
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, err := os.Stat(filepath.Join(dir, "helper-started")); err == nil {
						break
					}
					select {
					case result := <-captureDone:
						t.Fatalf("native helper failed: %v", result)
					default:
					}
					if time.Now().After(deadline) {
						t.Fatal("actual helper not started")
					}
					time.Sleep(time.Millisecond)
				}
			} else {
				waitCaptureEvent(t, h.ready, captureDone, "kernel exit before original Wait")
				t.Logf("native child %d is exited and unreaped before original Wait", h.pid)
			}
			window := time.Minute
			if tc.trigger == "timer" {
				window = time.Millisecond
			}
			commands := []string{fmt.Sprintf("printf captured > %q; chmod 0600 %q; printf 'once\n' >> %q", target, target, count), fmt.Sprintf("rm %q", absent)}
			if _, err := a.ArmDeadman("capture-ownership", window, commands); err != nil {
				t.Fatal(err)
			}
			if tc.trigger == "shutdown" {
				a.StartShutdown(nil)
			}
			waitClaim(t, a)
			later := dispatch(request)
			if later.GetError() == nil || later.GetError().GetCode() != "shutting_down" || h.calls.Load() != 1 {
				t.Fatalf("later Capture entered native work: %v calls=%d", later, h.calls.Load())
			}
			if h.original.Err() != nil {
				t.Fatalf("shutdown canceled natural Capture: %v", h.original.Err())
			}
			// An actual trigger has claimed recovery; it must wait, not reap the zombie.
			select {
			case result := <-captureDone:
				t.Fatalf("Capture completed without original Wait release: %v", result)
			case <-time.After(150 * time.Millisecond):
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "mutated" {
				t.Fatalf("recovery overtook Capture wait: %q %v", data, err)
			}
			if tc.trigger == "shutdown" {
				drain := make(chan error, 1)
				go func() { drain <- a.Drain() }()
				select {
				case err := <-drain:
					t.Fatalf("shutdown declared idle with Capture unjoined: %v", err)
				case <-time.After(550 * time.Millisecond):
				}
			}
			h.releaseWork()
			select {
			case result := <-captureDone:
				if result.GetError() != nil || result.GetCaptureResp() == nil {
					t.Fatalf("Capture lost native status/output: %v", result)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Capture did not naturally join")
			}
			report := <-h.report
			wantOutput := "native-output"
			if tc.variant == "helper" {
				wantOutput = "fixture-active"
			}
			if report.err != nil || report.code != tc.code || report.output != wantOutput {
				t.Fatalf("original native wait/status/output changed: %#v", report)
			}
			a.StartShutdown(nil)
			joined := make(chan error, 1)
			go func() { joined <- a.Drain() }()
			select {
			case err := <-joined:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("recovery did not join after native Capture completion")
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "captured" {
				t.Fatalf("captured bytes not restored: %q %v", data, err)
			}
			if st, err := os.Stat(target); err != nil || st.Mode().Perm() != 0600 {
				t.Fatalf("captured mode not restored: %v %v", st, err)
			}
			if _, err := os.Stat(absent); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("second restoration command lost: %v", err)
			}
			if data, err := os.ReadFile(count); err != nil || strings.TrimSpace(string(data)) != "once" {
				t.Fatalf("recovery not executed once: %q %v", data, err)
			}
		})
	}
}
