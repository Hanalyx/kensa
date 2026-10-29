//go:build linux

package deadman

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// @spec agent-stdio-subcommand
// @ac AC-10
func TestRejectedFirstArmDoesNotInitializeOwnership(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-10")
	if os.Getenv("KENSA_REJECTED_ARM_CONTROL") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestRejectedFirstArmDoesNotInitializeOwnership$", "-test.v")
		command.Env = append(os.Environ(), "KENSA_REJECTED_ARM_CONTROL=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated first-arm control: %v\n%s", err, output)
		}
		return
	}
	var before, after int32
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&before)), 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if before != 0 {
		t.Fatal("isolated fixture already initialized ownership")
	}
	a := New()
	a.StartShutdown(nil)
	if _, err := a.ArmDeadman("late-first", time.Minute, nil); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("late first arm: %v", err)
	}
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&after)), 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("rejected Arm initialized process ownership before checking shutdown")
	}
	if a.ActiveCount() != 0 {
		t.Fatal("rejected Arm allocated a reservation")
	}
}
