// Local-syscall api.Transport implementation for the agent
// process. L-014 deliverable per spec
// agent-handler-port-filepermissions C-01.
//
// **Context.** When the agent runs on the target host and
// invokes a Handler's Apply/Capture/Rollback, the
// `transport` argument is THIS — local exec, local file IO,
// no SSH involved. The agent IS the target's local
// execution surface.
//
// **Transport contract preserved.** Existing handlers
// (file_permissions, service_*, sysctl_set, etc.) call
// transport.Run / Put / Get without knowing whether they're
// running on the controller (via SSH) or the agent (via
// local exec). Option L1 in the L-014 design doc preserves
// this — handlers port to agent mode by being run under
// LocalTransport with NO source-level changes.

package local

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
	"github.com/Hanalyx/kensa/internal/agent/fsatomic"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/agent/systemd"
)

// Transport is the local-syscall implementation of
// api.Transport. Construct via New(); reuse across Apply /
// Capture / Rollback calls within a single transaction (it's
// stateless beyond the optional sudo configuration).
type Transport struct {
	// useSudo wraps Run commands in `sudo -n sh -c '...'`
	// when true. Matches the SSH transport's sudo
	// convention. The agent process typically runs as the
	// SSH user (often non-root); useSudo lets it escalate
	// for privileged operations.
	useSudo bool

	// sd is the systemd D-Bus helper client backing the
	// systemd.Transport capability methods. The service handlers
	// type-assert transport.(systemd.Transport) and, when present,
	// drive enable/disable/mask/unmask/start/stop/unit-state through
	// the privileged kensa-systemd-helper instead of shelling out to
	// `systemctl`. Defaults to systemd.New() (the packaged helper
	// path); nil-guarded by client() so a zero-value Transport still
	// works.
	sd *systemd.Client
}

// Option mutates the Transport during construction.
// Functional-options pattern matches the L-010 review's
// FramingOptions recommendation.
type Option func(*Transport)

// WithSudo enables sudo wrapping on Run commands. When the
// agent runs as a non-root SSH user, this lets handlers
// invoke privileged commands the same way the SSH transport
// does.
func WithSudo(b bool) Option {
	return func(t *Transport) { t.useSudo = b }
}

// New constructs a local Transport. Use Option helpers like
// WithSudo to configure explicitly. For auto-detection
// (sudo iff not running as root), use NewAuto.
func New(opts ...Option) *Transport {
	t := &Transport{}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// NewAuto constructs a local Transport with sudo enabled
// iff the current process is NOT running as root. This is
// the right default for `kensa agent --stdio` invoked over
// SSH — the SSH user is typically non-root in production
// deployments, so handlers needing privilege (chmod on
// system files, systemctl, etc.) require sudo wrapping.
// When already root, sudo is unnecessary and the wrap is
// skipped to avoid a `sudo: not found` failure on
// minimal-userspace targets.
//
// Per the L-014 peer-review fix: previously server.Handle
// called local.New() with no sudo, silently breaking
// production deployments where the SSH user isn't root.
func NewAuto() *Transport {
	return New(WithSudo(os.Geteuid() != 0))
}

// Run executes cmd via `sh -c` locally. Captures stdout and
// stderr separately, returns CommandResult with the trimmed
// outputs + exit code + duration.
//
// Sudo wrapping: when useSudo is set, the command becomes
// `sudo -n sh -c '...'` (non-interactive sudo — matches the
// SSH transport's convention). Handlers that need privilege
// escalation work transparently.
func (t *Transport) Run(ctx context.Context, cmd string) (*api.CommandResult, error) {
	shellCmd := cmd
	if t.useSudo {
		// Quote the command for sudo -n sh -c '...'. The
		// quoting is single-quote-with-internal-escaping
		// (same pattern as bootstrap.shellQuote).
		shellCmd = "sudo -n sh -c " + shellQuote(cmd)
	}
	c := exec.CommandContext(ctx, "sh", "-c", shellCmd)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	start := time.Now()
	err := c.Run()
	duration := time.Since(start)

	result := &api.CommandResult{
		Stdout:   strings.TrimRight(stdout.String(), "\n"),
		Stderr:   strings.TrimRight(stderr.String(), "\n"),
		Duration: duration,
	}
	if err != nil {
		// Distinguish "command ran but exited non-zero"
		// (ExitError → preserve exit code) from "couldn't
		// start the command at all" (other error →
		// surface as Go error).
		var exitErr *exec.ExitError
		if isExitError(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result, nil
		}
		return result, fmt.Errorf("local exec: %w", err)
	}
	result.ExitCode = 0
	return result, nil
}

// Put copies localPath → remotePath and sets the mode.
// "Remote" in agent mode means "another path on this same
// machine" — there is no remote host. The semantics match
// the SSH transport's Put for compatibility.
//
// **L-018 carry-forward**: Put is non-atomic (O_TRUNC on
// the destination). On partial write failure the file is
// left truncated/corrupt. Matches the SSH transport's scp-
// in-place behavior. For agent mode the cheap fix is
// write-to-`.kensa-tmp.<pid>` + os.Rename on success; this
// matters for file_content (L-018 port target) where open
// readers should see old-or-new, never truncated. Deferred.
func (t *Transport) Put(_ context.Context, localPath, remotePath string, mode fs.FileMode) error {
	src, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("local Put: open source %s: %w", localPath, err)
	}
	defer src.Close()

	// Create with the requested mode immediately so the
	// file is never visible to other readers at a more-
	// permissive mode mid-write. The umask gets applied,
	// so we follow up with explicit Chmod to enforce.
	dst, err := os.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("local Put: open dest %s: %w", remotePath, err)
	}
	if _, err := copyAndClose(dst, src); err != nil {
		return fmt.Errorf("local Put: copy %s → %s: %w", localPath, remotePath, err)
	}
	// Explicit chmod after close: handles the umask case
	// + ensures the requested mode is what's on disk
	// regardless of inherited umask.
	if err := os.Chmod(remotePath, mode); err != nil {
		return fmt.Errorf("local Put: chmod %s: %w", remotePath, err)
	}
	return nil
}

// Get copies remotePath → localPath. In agent mode this is
// a local-to-local copy. Mode is preserved from the source.
func (t *Transport) Get(_ context.Context, remotePath, localPath string) error {
	src, err := os.Open(remotePath)
	if err != nil {
		return fmt.Errorf("local Get: open source %s: %w", remotePath, err)
	}
	defer src.Close()
	srcInfo, err := src.Stat()
	if err != nil {
		return fmt.Errorf("local Get: stat source: %w", err)
	}
	dst, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("local Get: open dest %s: %w", localPath, err)
	}
	if _, err := copyAndClose(dst, src); err != nil {
		return fmt.Errorf("local Get: copy %s → %s: %w", remotePath, localPath, err)
	}
	return nil
}

// ControlChannelSensitive always returns false: the agent
// IS the target. There is no control channel to be
// disrupted by an in-flight change.
func (t *Transport) ControlChannelSensitive() bool { return false }

// Close is a no-op for LocalTransport. There's no SSH
// connection to tear down or temp directory to clean up.
func (t *Transport) Close() error { return nil }

// AtomicWrite delegates to fsatomic.AtomicWrite. Satisfies the
// fsatomic.Transport capability interface so handlers running
// under agent-mode can detect-and-use atomic primitives via
// type assertion.
func (t *Transport) AtomicWrite(ctx context.Context, dir, name string, mode fs.FileMode, content []byte) error {
	return fsatomic.AtomicWrite(ctx, dir, name, mode, content)
}

// AtomicReplace delegates to fsatomic.AtomicReplace.
func (t *Transport) AtomicReplace(ctx context.Context, fullPath string, mode fs.FileMode, content []byte) error {
	return fsatomic.AtomicReplace(ctx, fullPath, mode, content)
}

// AtomicRemove delegates to fsatomic.AtomicRemove.
func (t *Transport) AtomicRemove(ctx context.Context, fullPath string) error {
	return fsatomic.AtomicRemove(ctx, fullPath)
}

// client returns the systemd helper client, lazily defaulting to the
// packaged-helper-path Client so a zero-value Transport (constructed
// without New) still satisfies the systemd.Transport capability.
func (t *Transport) client() *systemd.Client {
	if t.sd == nil {
		t.sd = systemd.New()
	}
	return t.sd
}

// The systemd.Transport capability methods delegate to the helper
// client. They satisfy systemd.Transport so service handlers running
// under agent-mode can detect-and-use the privileged D-Bus helper via
// type assertion, exactly as the AtomicWrite/Replace/Remove methods
// satisfy fsatomic.Transport.

// Enable delegates to the systemd helper's enable op.
func (t *Transport) Enable(ctx context.Context, unit string) (*systemd.Response, error) {
	return t.client().Enable(ctx, unit)
}

// Disable delegates to the systemd helper's disable op.
func (t *Transport) Disable(ctx context.Context, unit string) (*systemd.Response, error) {
	return t.client().Disable(ctx, unit)
}

// Mask delegates to the systemd helper's mask op.
func (t *Transport) Mask(ctx context.Context, unit string) (*systemd.Response, error) {
	return t.client().Mask(ctx, unit)
}

// Unmask delegates to the systemd helper's unmask op.
func (t *Transport) Unmask(ctx context.Context, unit string) (*systemd.Response, error) {
	return t.client().Unmask(ctx, unit)
}

// Start delegates to the systemd helper's start op (JobRemoved-synced).
func (t *Transport) Start(ctx context.Context, unit string) (*systemd.Response, error) {
	return t.client().Start(ctx, unit)
}

// Stop delegates to the systemd helper's stop op (JobRemoved-synced).
func (t *Transport) Stop(ctx context.Context, unit string) (*systemd.Response, error) {
	return t.client().Stop(ctx, unit)
}

// UnitState delegates to the systemd helper's unit-state op (the rich
// Capture payload).
func (t *Transport) UnitState(ctx context.Context, unit string) (*systemd.Response, error) {
	return t.client().UnitState(ctx, unit)
}

// WriteSysctl delegates to kernelio.WriteSysctl (a direct /proc/sys
// write). Satisfies kernelio.SysctlTransport so the sysctl_set handler
// can detect-and-use direct kernel IO via type assertion.
func (t *Transport) WriteSysctl(key, value string) error {
	return kernelio.WriteSysctl(key, value)
}

// ReadSysctl delegates to kernelio.ReadSysctl (a direct /proc/sys read).
func (t *Transport) ReadSysctl(key string) (string, error) {
	return kernelio.ReadSysctl(key)
}

// ReadFileIfExists delegates to kernelio.ReadFileIfExists, the
// agent-side persist-file capture read.
func (t *Transport) ReadFileIfExists(path string) (string, bool, error) {
	return kernelio.ReadFileIfExists(path)
}

// DeleteModule delegates to kernelio.DeleteModule (delete_module(2)).
// Satisfies kernelio.ModuleTransport for the kernel_module_disable
// handler's runtime unload.
func (t *Transport) DeleteModule(name string) error {
	return kernelio.DeleteModule(name)
}

// AuditClient opens an AUDIT netlink client. Satisfies
// auditnl.AuditTransport for the audit_rule_set handler's runtime rule
// load/unload. A non-root / no-audit host gets a wrapped
// auditnl.ErrAuditUnavailable, sending the handler to its shell path.
func (t *Transport) AuditClient() (auditnl.AuditClient, error) {
	return auditnl.Open()
}

// Compile-time interface check.
var (
	_ api.Transport            = (*Transport)(nil)
	_ fsatomic.Transport       = (*Transport)(nil)
	_ systemd.Transport        = (*Transport)(nil)
	_ kernelio.SysctlTransport = (*Transport)(nil)
	_ kernelio.ModuleTransport = (*Transport)(nil)
	_ auditnl.AuditTransport   = (*Transport)(nil)
)
