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

	"github.com/Hanalyx/kensa-go/api"
)

// EnsureAgent pushes the kensa binary at localBinaryPath to
// the target via transport, caches it by SHA-256, and returns
// the absolute target path the controller invokes as
// `<remotePath> agent --stdio`.
//
// Cache layout: `$HOME/.cache/kensa/agent-<sha>` on the
// target, where $HOME is resolved at runtime via
// `transport.Run("printf '%s' \"$HOME\"")`.
//
// On cache hit (target file exists + executable), no push;
// returns immediately. On cache miss, mkdirs the cache dir,
// Puts the binary at the cache path with mode 0755, and
// verifies executability before returning.
//
// Concurrent-session race: two parallel calls targeting the
// same host may both hit the cache-miss path and both Put.
// mkdir is idempotent; Put overwrites with the same bytes
// (since the SHA is identical). Acceptable.
func EnsureAgent(ctx context.Context, transport api.Transport, localBinaryPath string) (string, error) {
	sha, err := sha256Hex(localBinaryPath)
	if err != nil {
		return "", fmt.Errorf("bootstrap: hash local binary %s: %w", localBinaryPath, err)
	}

	home, err := resolveTargetHome(ctx, transport)
	if err != nil {
		return "", fmt.Errorf("bootstrap: resolve $HOME on target: %w", err)
	}

	cacheDir := home + "/.cache/kensa"
	cachePath := cacheDir + "/agent-" + sha

	// Cache hit check.
	probe, err := transport.Run(ctx, fmt.Sprintf("test -x %s", shellQuote(cachePath)))
	if err != nil {
		return "", fmt.Errorf("bootstrap: cache probe failed: %w", err)
	}
	if probe.ExitCode == 0 {
		return cachePath, nil
	}

	// Cache miss: mkdir + Put + final test.
	mkResult, err := transport.Run(ctx, fmt.Sprintf("mkdir -p %s", shellQuote(cacheDir)))
	if err != nil {
		return "", fmt.Errorf("bootstrap: mkdir %s: %w", cacheDir, err)
	}
	if mkResult.ExitCode != 0 {
		return "", fmt.Errorf("bootstrap: mkdir %s failed (exit %d): %s", cacheDir, mkResult.ExitCode, mkResult.Stderr)
	}

	if err := transport.Put(ctx, localBinaryPath, cachePath, fs.FileMode(0o755)); err != nil {
		return "", fmt.Errorf("bootstrap: put %s → %s: %w", localBinaryPath, cachePath, err)
	}

	// Final exec-bit verification.
	final, err := transport.Run(ctx, fmt.Sprintf("test -x %s", shellQuote(cachePath)))
	if err != nil {
		return "", fmt.Errorf("bootstrap: post-push verify failed: %w", err)
	}
	if final.ExitCode != 0 {
		return "", fmt.Errorf("bootstrap: pushed binary at %s is not executable (test -x exit %d): %s",
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

// resolveTargetHome runs `printf '%s' "$HOME"` on the target
// and returns the trimmed value. Avoids embedding ~ or $HOME
// expansion assumptions into later commands.
func resolveTargetHome(ctx context.Context, transport api.Transport) (string, error) {
	result, err := transport.Run(ctx, `printf '%s' "$HOME"`)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("printf $HOME exit %d: %s", result.ExitCode, result.Stderr)
	}
	home := strings.TrimSpace(result.Stdout)
	if home == "" {
		return "", fmt.Errorf("$HOME resolved to empty string on target")
	}
	if !strings.HasPrefix(home, "/") {
		return "", fmt.Errorf("$HOME on target is not absolute: %q", home)
	}
	return home, nil
}

// shellQuote returns a single-quoted POSIX-shell string with
// any embedded single-quotes properly escaped. Used to
// construct safe shell commands from path strings that might
// contain spaces or other special characters. We use
// single-quote-end-quote-backslash-quote-start-quote: `O'Brien`
// becomes `'O'\''Brien'`.
//
// Note: in practice all paths used by L-013 are
// SHA-256-hex-suffixed under $HOME/.cache/kensa, so neither
// space nor quote chars appear. The quoting is defense-in-
// depth against a future code path that constructs paths
// from operator input.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
