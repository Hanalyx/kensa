package ownedexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

type nativeKey struct{}

// NativeStatus records uncertain native waits without canceling Capture or
// transferring exec.Cmd wait ownership to the process-wide reaper.
type NativeStatus struct {
	mu  sync.Mutex
	err error
}

type nativeUncertain struct{ cause error }

func (e *nativeUncertain) Error() string { return "UNRESOLVED native command wait: " + e.cause.Error() }
func (e *nativeUncertain) Unwrap() error { return e.cause }

// NativeContext preserves the parent's cancellation behavior and adds only
// wait-outcome accounting. In Capture the parent remains Background.
func NativeContext(parent context.Context) (context.Context, *NativeStatus) {
	status := &NativeStatus{}
	return context.WithValue(parent, nativeKey{}, status), status
}

// Err returns sticky uncertainty, including an error a handler later swallows.
func (s *NativeStatus) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }

// NativeUncertainty distinguishes uncertain waits from ordinary handler,
// validation, launch and settled-command failures.
func NativeUncertainty(err error) error {
	if err == nil {
		return nil
	}
	var uncertain *nativeUncertain
	if errors.As(err, &uncertain) {
		return uncertain
	}
	var call *os.SyscallError
	if errors.Is(err, syscall.ECHILD) || errors.Is(err, exec.ErrWaitDelay) || errors.As(err, &call) && (call.Syscall == "waitid" || call.Syscall == "wait4" || call.Syscall == "wait") {
		return &nativeUncertain{cause: err}
	}
	return nil
}

// NativeError refuses additional native launches after wait ownership is lost.
func NativeError(ctx context.Context) error {
	if status, ok := ctx.Value(nativeKey{}).(*NativeStatus); ok {
		return status.Err()
	}
	return nil
}

// ObserveNativeWait is called only after successful Start and actual Wait.
// A nil process state or incomplete pipe wait cannot certify completion. A
// settled nonzero/signal exit retains its existing ordinary result semantics.
func ObserveNativeWait(ctx context.Context, cmd *exec.Cmd, err error) error {
	if cmd.ProcessState == nil || errors.Is(err, exec.ErrWaitDelay) {
		if err == nil {
			err = errors.New("native Wait returned without process state")
		}
		uncertain := &nativeUncertain{cause: fmt.Errorf("pid %d: %w", cmd.Process.Pid, err)}
		if status, ok := ctx.Value(nativeKey{}).(*NativeStatus); ok {
			status.mu.Lock()
			status.err = errors.Join(status.err, uncertain)
			status.mu.Unlock()
		}
		return uncertain
	}
	return err
}
