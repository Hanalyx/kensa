package kernelio

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// ErrModuleNotLoaded is the sentinel a caller can use to recognize the
// "module was not loaded" outcome of an unload (delete_module → ENOENT).
// The kernel_module_disable handler treats it, like any unload failure,
// as a best-effort no-op: the persistent blacklist is what guarantees the
// module stays out; the runtime unload is opportunistic cleanup.
var ErrModuleNotLoaded = errors.New("kernelio: module not loaded")

// DeleteModule unloads a kernel module from the running kernel via the
// delete_module(2) syscall (the rmmod primitive). O_NONBLOCK makes the
// call return immediately rather than waiting for the module refcount to
// drain; a module that is in use returns EBUSY/EWOULDBLOCK. delete_module
// removes only the named module, not its now-unused dependencies (that
// dependency walk is a modprobe(8) nicety) — adequate here because the
// persistent blacklist+install-/bin/true entry is what actually keeps the
// module out, and this unload is best-effort cleanup of an already-loaded
// instance.
//
// ENOENT (module not loaded) is normalised to ErrModuleNotLoaded so the
// caller can distinguish it from a genuine failure.
func DeleteModule(name string) error {
	if name == "" {
		return errors.New("kernelio: empty module name")
	}
	if err := unix.DeleteModule(name, unix.O_NONBLOCK); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return ErrModuleNotLoaded
		}
		return fmt.Errorf("kernelio: delete_module %q: %w", name, err)
	}
	return nil
}
