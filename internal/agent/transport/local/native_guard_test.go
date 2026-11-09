//go:build linux

package local

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Hanalyx/kensa/internal/agent/ownedexec"
)

func TestNativeWaitUncertaintyRefusesLocalFallbackLaunch(t *testing.T) {
	ctx, _ := ownedexec.NativeContext(context.Background())
	child := exec.Command("/bin/sh", "-c", "exit 0")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Wait4(child.Process.Pid, nil, 0, nil); err != nil {
		t.Fatal(err)
	}
	_ = ownedexec.ObserveNativeWait(ctx, child, child.Wait())
	target := filepath.Join(t.TempDir(), "must-not-launch")
	_, err := New(WithSudo(false)).Run(ctx, "touch '"+target+"'")
	if !errors.Is(err, unix.ECHILD) {
		t.Fatalf("native wait uncertainty lost: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("fallback native command launched after lost wait: %v", err)
	}
}
