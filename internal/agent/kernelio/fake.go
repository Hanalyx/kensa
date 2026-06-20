package kernelio

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/fsatomic"
)

// FakeSysctlTransport is an in-memory test double implementing
// SysctlTransport (and therefore the embedded fsatomic.Transport). It
// models the runtime (proc) layer as a key→value map and the persistence
// (file) layer as a path→content map, so a test can exercise a full
// Apply → Capture → Rollback round trip without touching /proc or disk.
// Lives in the production package (a normal file, not _test.go) so the
// sysctlset handler tests can share it, mirroring servicedbus.FakeTransport.
type FakeSysctlTransport struct {
	Runtime map[string]string // sysctl key → value (the /proc/sys layer)
	Files   map[string]string // path → content (the persist layer)
	// WriteErr, keyed by sysctl key, simulates a kernel rejection (EINVAL)
	// on WriteSysctl for that key.
	WriteErr map[string]error

	// Runs records shell commands issued via Run (e.g. the mount handler's
	// remount, which stays on mount(8) even on the kernel-IO path).
	Runs []string

	// DeletedModules records DeleteModule calls (the module handler's
	// runtime unload). DeleteModuleErr, keyed by module name, injects an
	// unload error (e.g. ErrModuleNotLoaded or a busy module).
	DeletedModules  []string
	DeleteModuleErr map[string]error

	// Dirs records MkdirAll calls (the dconf handler's drop-in dirs).
	Dirs []string
}

// NewFakeSysctl returns a FakeSysctlTransport with initialized maps.
func NewFakeSysctl() *FakeSysctlTransport {
	return &FakeSysctlTransport{
		Runtime:         map[string]string{},
		Files:           map[string]string{},
		WriteErr:        map[string]error{},
		DeleteModuleErr: map[string]error{},
	}
}

// DeleteModule records the unload and returns any canned error.
func (f *FakeSysctlTransport) DeleteModule(name string) error {
	f.DeletedModules = append(f.DeletedModules, name)
	return f.DeleteModuleErr[name]
}

// WriteSysctl records the runtime value, or returns the canned WriteErr.
func (f *FakeSysctlTransport) WriteSysctl(key, value string) error {
	if err := f.WriteErr[key]; err != nil {
		return err
	}
	f.Runtime[key] = value
	return nil
}

// ReadSysctl returns the recorded runtime value (empty string if unset).
func (f *FakeSysctlTransport) ReadSysctl(key string) (string, error) {
	return f.Runtime[key], nil
}

// ReadFileIfExists serves the in-memory persist layer.
func (f *FakeSysctlTransport) ReadFileIfExists(path string) (string, bool, error) {
	c, ok := f.Files[path]
	return c, ok, nil
}

// MkdirAll records the directory (the in-memory Files layer needs no real
// dir for AtomicReplace/Write to succeed).
func (f *FakeSysctlTransport) MkdirAll(path string, _ fs.FileMode) error {
	f.Dirs = append(f.Dirs, path)
	return nil
}

// AtomicReplace writes content to an EXISTING in-memory file, modeling
// fsatomic.AtomicReplace: it errors fsatomic.ErrNotExist when the target
// is absent. (The earlier no-op map-set masked the live-caught bug where a
// handler used AtomicReplace on a not-yet-created drop-in.)
func (f *FakeSysctlTransport) AtomicReplace(_ context.Context, fullPath string, _ fs.FileMode, content []byte) error {
	if _, ok := f.Files[fullPath]; !ok {
		return fmt.Errorf("%w: %s", fsatomic.ErrNotExist, fullPath)
	}
	f.Files[fullPath] = string(content)
	return nil
}

// AtomicWrite creates a NEW in-memory file, modeling fsatomic.AtomicWrite:
// it errors fsatomic.ErrAlreadyExists when the target already exists.
func (f *FakeSysctlTransport) AtomicWrite(_ context.Context, dir, name string, _ fs.FileMode, content []byte) error {
	p := filepath.Join(dir, name)
	if _, ok := f.Files[p]; ok {
		return fmt.Errorf("%w: %s", fsatomic.ErrAlreadyExists, p)
	}
	f.Files[p] = string(content)
	return nil
}

// AtomicRemove deletes an EXISTING in-memory file, modeling
// fsatomic.AtomicRemove: it errors fsatomic.ErrNotExist when the target is
// absent.
func (f *FakeSysctlTransport) AtomicRemove(_ context.Context, fullPath string) error {
	if _, ok := f.Files[fullPath]; !ok {
		return fmt.Errorf("%w: %s", fsatomic.ErrNotExist, fullPath)
	}
	delete(f.Files, fullPath)
	return nil
}

// api.Transport methods. The kernel-IO path never calls these, but the
// handler signature takes api.Transport, so the fake must satisfy it to
// be passed in. Run defaults to success; the shell path is never reached
// because the handler's type assertion to SysctlTransport succeeds.

// Run records the command and returns success. The sysctl kernel-IO
// path never calls it; the mount kernel-IO path uses it for the remount.
func (f *FakeSysctlTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	f.Runs = append(f.Runs, cmd)
	return &api.CommandResult{ExitCode: 0}, nil
}

// Put is a no-op.
func (f *FakeSysctlTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }

// Get is a no-op.
func (f *FakeSysctlTransport) Get(_ context.Context, _, _ string) error { return nil }

// ControlChannelSensitive reports false.
func (f *FakeSysctlTransport) ControlChannelSensitive() bool { return false }

// Close is a no-op.
func (f *FakeSysctlTransport) Close() error { return nil }

// failingFakeSysctl wraps FakeSysctlTransport to force AtomicReplace/
// AtomicRemove errors, for the rollback/apply persist-failure paths.
type failingFakeSysctl struct {
	*FakeSysctlTransport
	replaceErr error
	removeErr  error
}

// NewFailingFakeSysctl returns a fake whose persist writes/removes fail
// with the given errors (nil = succeed).
func NewFailingFakeSysctl(replaceErr, removeErr error) SysctlTransport {
	return &failingFakeSysctl{FakeSysctlTransport: NewFakeSysctl(), replaceErr: replaceErr, removeErr: removeErr}
}

func (f *failingFakeSysctl) AtomicReplace(ctx context.Context, p string, m fs.FileMode, c []byte) error {
	if f.replaceErr != nil {
		return fmt.Errorf("fake replace: %w", f.replaceErr)
	}
	return f.FakeSysctlTransport.AtomicReplace(ctx, p, m, c)
}

func (f *failingFakeSysctl) AtomicRemove(ctx context.Context, p string) error {
	if f.removeErr != nil {
		return fmt.Errorf("fake remove: %w", f.removeErr)
	}
	return f.FakeSysctlTransport.AtomicRemove(ctx, p)
}

// Compile-time assertions.
var (
	_ SysctlTransport = (*FakeSysctlTransport)(nil)
	_ ModuleTransport = (*FakeSysctlTransport)(nil)
	_ api.Transport   = (*FakeSysctlTransport)(nil)
)
