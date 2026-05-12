// Package pidfd wraps Linux's pidfd_open(2) for race-free
// parent-death detection in the rebuilt agent-side deadman
// subsystem.
//
// **Why pidfd.** The agent is spawned by SSH. If the SSH
// connection drops, the agent's parent process terminates.
// The agent's event loop (D-004) needs a race-free way to
// detect this so it can fire the in-process rollback BEFORE
// the agent itself dies. Traditional approaches (SIGCHLD,
// polling getppid()==1, prctl(PR_SET_PDEATHSIG)) all have
// races or limitations; pidfd_open opens a file descriptor
// tied to the parent's process identity (not its PID, which
// can be reused) and the fd becomes POLLIN-readable when
// the process exits.
//
// **Kernel floor.** pidfd_open requires kernel ≥ 5.3. RHEL 8
// ships 4.18 — too old. Use ProbeSupport() to detect at
// runtime; callers fall back to D-003's
// prctl(PR_SET_PDEATHSIG, SIGKILL) for parent-death
// detection on older kernels (Q2.b ratification, 2026-05-12).
//
// **Concurrency contract.**
//   - ProbeSupport: safe to call from any goroutine; result
//     cached via sync.Once.
//   - Open / OpenParent / FD / Close: safe to call from any
//     goroutine.
//   - Wait: one goroutine at a time. Close DOES unblock Wait
//     safely via the poll-loop's closed-flag check.
//
// Spec: specs/deadman/pidfd.spec.yaml (D-002).
package pidfd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ErrKernelTooOld is returned by ProbeSupport when the
// running kernel doesn't support pidfd_open (kernel < 5.3,
// detected via ENOSYS). Callers should fall back to
// prctl(PR_SET_PDEATHSIG) via the D-003 signalfd package.
var ErrKernelTooOld = errors.New("pidfd: pidfd_open unsupported on this kernel (requires ≥5.3)")

// ErrPidfdBlocked is returned by ProbeSupport when the
// kernel supports pidfd_open but a security policy (seccomp,
// Docker default profile on older versions, hardened
// containers) blocks the syscall — detected via EPERM or
// EACCES. Callers should fall back to prctl as if the kernel
// were too old.
var ErrPidfdBlocked = errors.New("pidfd: pidfd_open blocked by security policy (seccomp/capabilities)")

// ErrClosed is returned by methods on a Pidfd that has
// already been Close()d.
var ErrClosed = errors.New("pidfd: pidfd is closed")

// ErrParentGone is returned by OpenParent when getppid()
// returns 0 or 1 — meaning the parent has already exited
// and the process has been reparented to init (or is itself
// init). The caller's deadman should treat this as
// "parent already dead, fire rollback immediately" rather
// than open a pidfd on init that will never fire.
var ErrParentGone = errors.New("pidfd: parent process has already exited (reparented to init)")

// pollInterval matches the timerfd package — 50ms wakeup
// for ctx/closed checks.
const pollInterval = 50

var (
	probeOnce   sync.Once
	probeResult error
)

// ProbeSupport returns nil if pidfd_open works on this
// kernel, ErrKernelTooOld if not, or a wrapped error for
// other probe failures.
//
// Safe to call concurrently; result cached via sync.Once.
// The probe opens a pidfd for the current process (which
// always exists) and closes it immediately.
func ProbeSupport() error {
	probeOnce.Do(func() {
		fd, err := unix.PidfdOpen(os.Getpid(), 0)
		if err != nil {
			switch {
			case errors.Is(err, unix.ENOSYS):
				probeResult = ErrKernelTooOld
			case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
				// seccomp / hardened-container blocked the
				// syscall; treat as fallback-equivalent.
				probeResult = ErrPidfdBlocked
			default:
				probeResult = fmt.Errorf("pidfd: probe failed: %w", err)
			}
			return
		}
		_ = unix.Close(fd)
		probeResult = nil
	})
	return probeResult
}

// Pidfd wraps a Linux pidfd_open(2) file descriptor.
//
// The fd becomes POLLIN-readable when the referenced process
// exits, regardless of whether that process is a child of
// the current one. Use for race-free parent-death detection
// in D-005's event loop.
type Pidfd struct {
	fd     int
	pid    int
	closed atomic.Bool
	mu     sync.Mutex
}

// Open opens a pidfd for the given PID.
//
// **CLOEXEC.** Linux kernels 5.10+ set close-on-exec
// implicitly on pidfd_open. On kernels 5.3-5.9 the fd
// inherits the default (no CLOEXEC). We always set
// FD_CLOEXEC explicitly via fcntl after open so the
// behavior is uniform across the supported kernel range.
//
// Returns ErrKernelTooOld / ErrPidfdBlocked if the probe
// indicated pidfd_open is unavailable. Returns a wrapped
// unix.ESRCH if pid doesn't exist.
func Open(pid int) (*Pidfd, error) {
	if err := ProbeSupport(); err != nil {
		return nil, err
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd: open pid %d: %w", pid, err)
	}
	// Explicit FD_CLOEXEC — kernel 5.3-5.9 doesn't set it
	// automatically; D-005 may fork-exec rollback commands.
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("pidfd: set CLOEXEC on fd: %w", err)
	}
	return &Pidfd{fd: fd, pid: pid}, nil
}

// OpenParent opens a pidfd for the current process's parent
// (unix.Getppid()). Convenience for D-005's deadman event
// loop: if the parent dies, the pidfd fires.
//
// Returns ErrParentGone if Getppid() returns 0 or 1 — the
// process is either init itself OR has already been
// reparented because the original parent exited. In either
// case opening a pidfd would either fail or wait forever;
// D-005 should treat this as "parent already dead, fire
// rollback now."
func OpenParent() (*Pidfd, error) {
	ppid := unix.Getppid()
	if ppid <= 1 {
		return nil, ErrParentGone
	}
	return Open(ppid)
}

// FD returns the underlying file descriptor for epoll
// registration (D-004). Returns -1 if Close was called.
func (p *Pidfd) FD() int {
	if p.closed.Load() {
		return -1
	}
	return p.fd
}

// PID returns the process ID this pidfd refers to. Useful
// for diagnostics; the pidfd's identity is tied to the
// process's start-time, not its PID, so the PID is just an
// informational tag.
func (p *Pidfd) PID() int {
	return p.pid
}

// Wait blocks until the referenced process exits OR ctx is
// canceled OR Close is called. Returns nil on process exit;
// ctx.Err() on context cancel; ErrClosed if Close happens
// during the wait.
//
// Same poll-based pattern as the timerfd package — avoids
// the Go-on-Linux fd-reuse footgun on parked blocking
// reads.
func (p *Pidfd) Wait(ctx context.Context) error {
	if p.closed.Load() {
		return ErrClosed
	}
	for {
		if p.closed.Load() {
			return ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		pollFds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pollFds, pollInterval)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if p.closed.Load() {
				return ErrClosed
			}
			return fmt.Errorf("pidfd: poll: %w", err)
		}
		if n == 0 {
			continue
		}
		if pollFds[0].Revents&unix.POLLNVAL != 0 {
			return ErrClosed
		}
		if pollFds[0].Revents&unix.POLLIN != 0 {
			// Parent exited.
			return nil
		}
	}
}

// Close releases the pidfd. Idempotent.
//
// Safe to call concurrently with a pending Wait — the poll
// loop observes the closed flag and exits before this method's
// unix.Close runs.
func (p *Pidfd) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// 2× pollInterval drain so any concurrent Wait observes
	// closed=true and exits its poll loop before we close
	// the fd.
	time.Sleep(2 * pollInterval * time.Millisecond)
	if err := unix.Close(p.fd); err != nil && !errors.Is(err, unix.EBADF) {
		return fmt.Errorf("pidfd: close: %w", err)
	}
	return nil
}
