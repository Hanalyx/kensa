package footprint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/agent/systemd"
)

// Compile-time assertions: the recorder is a transparent stand-in for the
// agent transport, so every capability a handler may assert is satisfied.
// systemd.Transport and auditnl.AuditTransport are forwarded unchanged (the
// service and audit_rule_set handlers select their agent path by asserting
// them) — omitting them silently routed those handlers to their shell
// fallback once the recorder began wrapping every apply.
var (
	_ api.Transport            = (*Recorder)(nil)
	_ kernelio.FileTransport   = (*Recorder)(nil)
	_ kernelio.SysctlTransport = (*Recorder)(nil)
	_ kernelio.ModuleTransport = (*Recorder)(nil)
	_ systemd.Transport        = (*Recorder)(nil)
	_ auditnl.AuditTransport   = (*Recorder)(nil)
)

// Inspector reads the canonical path and restorable pre-image of a resource
// BEFORE it is mutated. The default (realInspect) uses the local filesystem
// — the agent runs on the target host — and tests inject a fake so they need
// no real files.
type Inspector func(path string) (canonical string, pre PreImage, err error)

// Recorder wraps the agent's transport and records every filesystem mutation
// it funnels — the OBSERVED footprint — so the engine can later assert
// observed ⊆ captured before commit. It mirrors internal/check/evidence.go:
// the handler calls the same capability methods as before; the wrapper
// records what they touched (with the pre-image read synchronously BEFORE
// each mutating syscall) and otherwise delegates unchanged.
//
// It transparently implements every capability interface the agent transport
// offers (fsatomic.Transport, kernelio.FileTransport / SysctlTransport /
// ModuleTransport), so a handler's type assertion still selects the agent
// path. Only filesystem mutations are recorded in this layer; runtime
// resources (sysctl keys, modules) are forwarded unchanged — their footprint
// is a later increment, and their persistent drop-in files (which DO flow
// through the recorded fsatomic methods) are already covered.
type Recorder struct {
	api.Transport // Run/Put/Get/Close/ControlChannelSensitive passthrough

	file    kernelio.FileTransport
	sysctl  kernelio.SysctlTransport
	module  kernelio.ModuleTransport
	systemd systemd.Transport
	audit   auditnl.AuditTransport
	fp      *Footprint
	inspect Inspector
}

// NewRecorder wraps inner (the agent's full-capability local transport).
// Capability views absent on inner are nil — a defensive case that does not
// arise in agent mode, where the local transport implements them all.
func NewRecorder(inner api.Transport) *Recorder {
	r := &Recorder{Transport: inner, fp: New(), inspect: realInspect}
	r.file, _ = inner.(kernelio.FileTransport)
	r.sysctl, _ = inner.(kernelio.SysctlTransport)
	r.module, _ = inner.(kernelio.ModuleTransport)
	r.systemd, _ = inner.(systemd.Transport)
	r.audit, _ = inner.(auditnl.AuditTransport)
	return r
}

// Footprint returns the observed footprint accumulated so far.
func (r *Recorder) Footprint() *Footprint { return r.fp }

// errNoCapability is returned when a method is called but inner did not
// provide the backing capability (does not occur in agent mode).
var errNoCapability = errors.New("footprint: wrapped transport lacks this capability")

// record inspects path before a mutation and appends the observed entry.
// op is the mutation kind; an absent pre-image forces OpCreate regardless,
// since there is nothing to restore but the resource's removal.
func (r *Recorder) record(path string, op Op) error {
	canon, pre, err := r.inspect(path)
	if err != nil {
		return fmt.Errorf("footprint: inspect %s: %w", path, err)
	}
	if pre.Absent {
		op = OpCreate
	}
	r.fp.Add(Entry{Path: canon, Op: op, PreImage: pre})
	return nil
}

// AtomicWrite records the new file (pre-image absent → create) then delegates.
func (r *Recorder) AtomicWrite(ctx context.Context, dir, name string, mode fs.FileMode, content []byte) error {
	if r.file == nil {
		return errNoCapability
	}
	if err := r.record(filepath.Join(dir, name), OpCreate); err != nil {
		return err
	}
	return r.file.AtomicWrite(ctx, dir, name, mode, content)
}

// AtomicReplace records the prior content of fullPath (modify, or create if
// absent) then delegates.
func (r *Recorder) AtomicReplace(ctx context.Context, fullPath string, mode fs.FileMode, content []byte) error {
	if r.file == nil {
		return errNoCapability
	}
	if err := r.record(fullPath, OpModify); err != nil {
		return err
	}
	return r.file.AtomicReplace(ctx, fullPath, mode, content)
}

// AtomicRemove records the prior content of fullPath (delete) then delegates.
func (r *Recorder) AtomicRemove(ctx context.Context, fullPath string) error {
	if r.file == nil {
		return errNoCapability
	}
	if err := r.record(fullPath, OpDelete); err != nil {
		return err
	}
	return r.file.AtomicRemove(ctx, fullPath)
}

// ReadFileIfExists is a read; it delegates unchanged (not recorded).
func (r *Recorder) ReadFileIfExists(path string) (string, bool, error) {
	if r.file == nil {
		return "", false, errNoCapability
	}
	return r.file.ReadFileIfExists(path)
}

// MkdirAll records each directory level it will CREATE (decomposed per
// level — a level that already exists is not a mutation) then delegates.
func (r *Recorder) MkdirAll(path string, mode fs.FileMode) error {
	if r.file == nil {
		return errNoCapability
	}
	for _, level := range missingDirLevels(path, r.inspect) {
		r.fp.Add(Entry{Path: level, Op: OpCreate, PreImage: PreImage{Absent: true, IsDir: true}})
	}
	return r.file.MkdirAll(path, mode)
}

// WriteSysctl forwards unchanged (runtime resource; persistent drop-in is
// recorded via the fsatomic methods).
func (r *Recorder) WriteSysctl(key, value string) error {
	if r.sysctl == nil {
		return errNoCapability
	}
	return r.sysctl.WriteSysctl(key, value)
}

// ReadSysctl is a read; forwards unchanged.
func (r *Recorder) ReadSysctl(key string) (string, error) {
	if r.sysctl == nil {
		return "", errNoCapability
	}
	return r.sysctl.ReadSysctl(key)
}

// DeleteModule forwards unchanged (runtime resource).
func (r *Recorder) DeleteModule(name string) error {
	if r.module == nil {
		return errNoCapability
	}
	return r.module.DeleteModule(name)
}

// systemd.Transport passthrough — the service handlers drive systemd units
// through the privileged D-Bus helper (not the filesystem), so there is
// nothing to record; the recorder forwards each call so a handler's
// transport.(systemd.Transport) assertion still selects the agent D-Bus path.

// Enable forwards to the wrapped systemd transport.
func (r *Recorder) Enable(ctx context.Context, unit string) (*systemd.Response, error) {
	if r.systemd == nil {
		return nil, errNoCapability
	}
	return r.systemd.Enable(ctx, unit)
}

// Disable forwards to the wrapped systemd transport.
func (r *Recorder) Disable(ctx context.Context, unit string) (*systemd.Response, error) {
	if r.systemd == nil {
		return nil, errNoCapability
	}
	return r.systemd.Disable(ctx, unit)
}

// Mask forwards to the wrapped systemd transport.
func (r *Recorder) Mask(ctx context.Context, unit string) (*systemd.Response, error) {
	if r.systemd == nil {
		return nil, errNoCapability
	}
	return r.systemd.Mask(ctx, unit)
}

// Unmask forwards to the wrapped systemd transport.
func (r *Recorder) Unmask(ctx context.Context, unit string) (*systemd.Response, error) {
	if r.systemd == nil {
		return nil, errNoCapability
	}
	return r.systemd.Unmask(ctx, unit)
}

// Start forwards to the wrapped systemd transport.
func (r *Recorder) Start(ctx context.Context, unit string) (*systemd.Response, error) {
	if r.systemd == nil {
		return nil, errNoCapability
	}
	return r.systemd.Start(ctx, unit)
}

// Stop forwards to the wrapped systemd transport.
func (r *Recorder) Stop(ctx context.Context, unit string) (*systemd.Response, error) {
	if r.systemd == nil {
		return nil, errNoCapability
	}
	return r.systemd.Stop(ctx, unit)
}

// UnitState forwards to the wrapped systemd transport.
func (r *Recorder) UnitState(ctx context.Context, unit string) (*systemd.Response, error) {
	if r.systemd == nil {
		return nil, errNoCapability
	}
	return r.systemd.UnitState(ctx, unit)
}

// AuditClient forwards to the wrapped audit transport. The netlink rule
// load/unload is not a filesystem mutation, so it is not recorded; the
// audit drop-in file IS recorded via the fsatomic methods above. Forwarding
// keeps the handler's transport.(auditnl.AuditTransport) assertion selecting
// the agent netlink path instead of the augenrules shell fallback.
func (r *Recorder) AuditClient() (auditnl.AuditClient, error) {
	if r.audit == nil {
		return nil, auditnl.ErrAuditUnavailable
	}
	return r.audit.AuditClient()
}

// missingDirLevels returns the canonical ancestor directories of path
// (shallowest first) that do not yet exist — the levels a MkdirAll will
// create. inspect reports absence per level.
func missingDirLevels(path string, inspect Inspector) []string {
	clean := filepath.Clean(path)
	var chain []string
	for p := clean; ; {
		chain = append([]string{p}, chain...)
		parent := filepath.Dir(p)
		if parent == p { // reached root
			break
		}
		p = parent
	}
	var missing []string
	for _, level := range chain {
		canon, pre, err := inspect(level)
		if err != nil {
			continue // unreadable level: skip recording, MkdirAll will surface it
		}
		if pre.Absent {
			missing = append(missing, canon)
		}
	}
	return missing
}

// realInspect reads the canonical path + pre-image from the local
// filesystem. Symlinks are refused (matching the fsatomic contract).
func realInspect(path string) (string, PreImage, error) {
	canon := Canonicalize(path)
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return canon, PreImage{Absent: true}, nil
	}
	if err != nil {
		return canon, PreImage{}, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return canon, PreImage{}, fmt.Errorf("refusing symlink %s", path)
	}
	pre := PreImage{Mode: fi.Mode(), IsDir: fi.IsDir()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		pre.UID = st.Uid
		pre.GID = st.Gid
	}
	if !fi.IsDir() {
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return canon, PreImage{}, rerr
		}
		pre.Size = int64(len(b))
		sum := sha256.Sum256(b)
		pre.SHA256 = hex.EncodeToString(sum[:])
	}
	return canon, pre, nil
}

// Canonicalize returns the lexical canonical form of path (filepath.Clean):
// it collapses "." / ".." / duplicate separators so the observed and
// captured footprints compare on the same key. It deliberately does NOT
// resolve symlinks: the underlying fsatomic primitives refuse any symlinked
// component (O_NOFOLLOW) at write time, so a symlinked parent never produces
// an observed mutation to reconcile — and resolving symlinks here would make
// the gate's invariant depend on a sibling component's policy rather than on
// its own deterministic, side-effect-free transform.
func Canonicalize(path string) string {
	return filepath.Clean(path)
}
