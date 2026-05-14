// Agent-binary push and SHA-cache layer. L-013 deliverable
// per spec agent-bootstrap.
//
// **Why this exists.** Agent-mode requires the kensa binary
// to be present on the target before `<remotePath> agent
// --stdio` can be invoked. EnsureAgent puts it there, caches
// it by SHA, and returns the invocable path.
//
// **Not part of the wire protocol.** The push happens BEFORE
// `kensa agent --stdio` starts. L-010's framed wire is
// uninvolved — the binary travels as raw bytes via
// api.Transport.Put (typically scp under the hood). L-010's
// 16 MiB frame cap does not apply.

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// systemCacheDir is the FHS-correct system-wide variable-cache
// path for the agent binary. Root-owned; the kensa-rpm
// packaging deliverable creates it at install time. The
// per-binary SHA in the filename is the cache key — different
// kensa versions coexist in this directory without conflict.
const systemCacheDir = "/var/cache/kensa"

// stageDir is the user-writable staging area for the
// scp-then-sudo-install dance. /var/tmp is world-writable +
// sticky on every supported distro AND (unlike /tmp on
// CIS-hardened RHEL hosts) is not typically mounted noexec.
// The staged file is removed once installed.
const stageDir = "/var/tmp"

// EnsureAgent pushes the kensa binary at localBinaryPath to
// the target via transport, caches it by SHA-256 at a
// root-owned system path, and returns the absolute target
// path the controller invokes as `<remotePath> agent --stdio`.
//
// **Cache layout: `/var/cache/kensa/agent-<sha>` on the target.**
// Root-owned so an attacker who compromises the SSH user
// can't tamper with the binary between the cache-hit check
// and the sudo invocation. The kensa-rpm packaging deliverable
// pre-creates `/var/cache/kensa/` at install time; this
// function creates it on demand (via `mkdir -p` which is
// sudo-wrapped when the transport is sudo-configured).
//
// **The stage-then-install dance.** `api.Transport.Put` is
// implemented via scp/sftp, which runs as the SSH user — not
// root, even when the transport is sudo-configured (sudo
// wraps the Run interactive path only). To land a binary in
// a root-owned cache, EnsureAgent:
//
//  1. Stages the upload at `/var/tmp/kensa-stage-<sha>` (any
//     SSH user can write there; sticky-bit dirs).
//  2. Runs `install -m 0755 <stage> <cache>` (Run uses sudo
//     so install executes as root; the file lands
//     root-owned).
//  3. Removes the stage file.
//  4. Verifies via `test -x <cache>`.
//
// Pre-B1 (2026-05-13) the bootstrap put the binary at
// `$HOME/.cache/kensa/agent-<sha>` where $HOME was resolved
// via a sudo'd `printf '%s' "$HOME"` — under --sudo that
// returned `/root`, but the subsequent scp ran as the SSH
// user (e.g., owadmin) and failed with "Permission denied"
// trying to write to /root/.cache. The asymmetry was
// surfaced by the live test on 192.168.1.211.
//
// On cache hit (target file exists + executable), no push;
// returns immediately. On cache miss, runs the stage→install
// dance + verification.
//
// Concurrent-session race: two parallel calls targeting the
// same host may both hit the cache-miss path. The `install`
// step is atomic (rename under the hood); both succeed and
// write byte-identical content (the SHA is the cache key).
func EnsureAgent(ctx context.Context, transport api.Transport, localBinaryPath string) (string, error) {
	sha, err := sha256Hex(localBinaryPath)
	if err != nil {
		return "", fmt.Errorf("bootstrap: hash local binary %s: %w", localBinaryPath, err)
	}

	cachePath := systemCacheDir + "/agent-" + sha
	stagePath := stageDir + "/kensa-stage-" + sha

	// Cache hit check.
	probe, err := transport.Run(ctx, fmt.Sprintf("test -x %s", shellQuote(cachePath)))
	if err != nil {
		return "", fmt.Errorf("bootstrap: cache probe failed: %w", err)
	}
	if probe.ExitCode == 0 {
		return cachePath, nil
	}

	// Cache miss: ensure the cache dir exists. mkdir -p under
	// sudo creates /var/cache/kensa as root:root mode 0755.
	mkResult, err := transport.Run(ctx, fmt.Sprintf("mkdir -p %s", shellQuote(systemCacheDir)))
	if err != nil {
		return "", fmt.Errorf("bootstrap: mkdir %s: %w", systemCacheDir, err)
	}
	if mkResult.ExitCode != 0 {
		return "", fmt.Errorf("bootstrap: mkdir %s failed (exit %d): %s",
			systemCacheDir, mkResult.ExitCode, mkResult.Stderr)
	}

	// Stage upload. transport.Put runs as the SSH user (scp/sftp
	// does not honor sudo); /var/tmp is universally writable +
	// sticky so this works for any non-root SSH user.
	if err := transport.Put(ctx, localBinaryPath, stagePath, fs.FileMode(0o755)); err != nil {
		return "", fmt.Errorf("bootstrap: stage %s → %s: %w",
			localBinaryPath, stagePath, err)
	}

	// Install + cleanup in one sudo'd pipeline so a partial
	// state (staged-but-not-installed) doesn't survive.
	installCmd := fmt.Sprintf("install -m 0755 %s %s && rm -f %s",
		shellQuote(stagePath), shellQuote(cachePath), shellQuote(stagePath))
	installRes, err := transport.Run(ctx, installCmd)
	if err != nil {
		// Best-effort cleanup of stage file.
		_, _ = transport.Run(ctx, fmt.Sprintf("rm -f %s", shellQuote(stagePath)))
		return "", fmt.Errorf("bootstrap: install %s → %s: %w",
			stagePath, cachePath, err)
	}
	if installRes.ExitCode != 0 {
		_, _ = transport.Run(ctx, fmt.Sprintf("rm -f %s", shellQuote(stagePath)))
		return "", fmt.Errorf("bootstrap: install %s → %s failed (exit %d): %s",
			stagePath, cachePath, installRes.ExitCode, installRes.Stderr)
	}

	// Final exec-bit verification at the cache path.
	final, err := transport.Run(ctx, fmt.Sprintf("test -x %s", shellQuote(cachePath)))
	if err != nil {
		return "", fmt.Errorf("bootstrap: post-install verify failed: %w", err)
	}
	if final.ExitCode != 0 {
		return "", fmt.Errorf("bootstrap: installed binary at %s is not executable (test -x exit %d): %s",
			cachePath, final.ExitCode, final.Stderr)
	}
	return cachePath, nil
}

// sha256Hex computes the lower-hex SHA-256 of a file via
// streaming hash. Matches kensa-keygen + evidence.computeKeyID
// hex format (64 lower-case chars).
func sha256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// shellQuote returns a single-quoted POSIX-shell string with
// any embedded single-quotes properly escaped. Used to
// construct safe shell commands from path strings that might
// contain spaces or other special characters. We use
// single-quote-end-quote-backslash-quote-start-quote: `O'Brien`
// becomes `'O'\”Brien'`.
//
// Note: in practice all paths used by L-013 are
// SHA-256-hex-suffixed under $HOME/.cache/kensa, so neither
// space nor quote chars appear. The quoting is defense-in-
// depth against a future code path that constructs paths
// from operator input.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
