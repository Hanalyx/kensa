//go:build linux

package systemd

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

func TestNativeWaitUncertaintyRefusesHelperLaunch(t *testing.T) {
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
	_, _, _, err := execHelper(ctx, []string{"/bin/sh", "-c", "touch '" + target + "'"})
	if !errors.Is(err, unix.ECHILD) {
		t.Fatalf("helper wait uncertainty lost: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("native helper launched after lost wait: %v", err)
	}
}
