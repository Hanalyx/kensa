//go:build linux

package ownedexec

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeWaitSettledExitIsOrdinary(t *testing.T) {
	for _, command := range []string{"exit 0", "exit 7"} {
		ctx, status := NativeContext(context.Background())
		cmd := exec.Command("/bin/sh", "-c", command)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		err := cmd.Wait()
		observed := ObserveNativeWait(ctx, cmd, err)
		if status.Err() != nil || NativeUncertainty(observed) != nil {
			t.Fatalf("settled result became uncertain: %v", observed)
		}
		if (err == nil) != (observed == nil) {
			t.Fatalf("ordinary native status changed: %v %v", err, observed)
		}
	}
}
func TestNativeWaitLossIsStickyWithoutCancelingContext(t *testing.T) {
	ctx, status := NativeContext(context.Background())
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Wait4(cmd.Process.Pid, nil, 0, nil); err != nil {
		t.Fatal(err)
	}
	err := ObserveNativeWait(ctx, cmd, cmd.Wait())
	if !errors.Is(err, unix.ECHILD) || NativeUncertainty(err) == nil || status.Err() == nil || NativeError(ctx) == nil {
		t.Fatalf("wait loss not retained: %v", err)
	}
	if ctx.Err() != nil || IsOwned(ctx) {
		t.Fatal("natural Capture became canceled or mutation-owned")
	}
}
