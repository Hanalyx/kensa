package bootguard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/Hanalyx/kensa/api"
)

// Restore writes a captured [Snapshot] back to the host and, on legacy
// (non-BLS) systems, regenerates grub.cfg. It is the counterpart to [Capture]:
// given a snapshot taken before a change, it returns the host's boot
// configuration to that captured state.
//
// MUTATING: Restore rewrites /etc/default/grub (and, on BLS, the captured
// BootLoaderSpec entry files) and may run the bootloader config generator.
// It must run over a privileged (Sudo) transport.
//
// On BLS (RHEL 8/9/10) the per-entry options= lines are authoritative, so
// Restore writes the captured entry files back verbatim and does NOT run
// grub2-mkconfig — regenerating would rebuild entries from GRUB_CMDLINE_LINUX
// and lose the per-entry args. On legacy (Ubuntu) GRUB_CMDLINE_LINUX is the
// source, so Restore writes it back and runs update-grub.
//
// Restore mutates live boot configuration, so per the project's
// rollback-handler discipline it requires a founder-authored failure-mode
// analysis and two-human review before it backs production remediation
// (CONTRIBUTING.md).
func Restore(ctx context.Context, t api.Transport, snap *Snapshot) error {
	if snap == nil {
		return errors.New("bootguard: Restore called with nil snapshot")
	}

	// /etc/default/grub is restored on every flavor.
	if err := writeRemoteFile(ctx, t, defaultGrubPath, snap.DefaultGrub); err != nil {
		return err
	}

	switch snap.Flavor {
	case FlavorBLS:
		// Entry options= lines are authoritative on BLS; restore them
		// verbatim and do NOT regenerate (mkconfig would clobber them).
		for path, content := range snap.BLSEntries {
			if err := writeRemoteFile(ctx, t, path, content); err != nil {
				return err
			}
		}
	case FlavorLegacy:
		// GRUB_CMDLINE_LINUX is the source on legacy; regenerate grub.cfg.
		cmd := "update-grub"
		if snap.GrubCfgPath != "" {
			cmd = fmt.Sprintf("update-grub 2>/dev/null || grub-mkconfig -o %s", shellQuote(snap.GrubCfgPath))
		}
		res, err := t.Run(ctx, cmd)
		if err != nil {
			return fmt.Errorf("bootguard: regenerate transport error: %w", err)
		}
		if !res.OK() {
			return fmt.Errorf("bootguard: grub regenerate failed (exit %d): %s", res.ExitCode, res.Stderr)
		}
	default:
		return fmt.Errorf("bootguard: Restore: unknown flavor %q", snap.Flavor)
	}
	return nil
}

// writeRemoteFile writes content to path via base64 to avoid shell-escaping
// pitfalls with arbitrary file content. Over a Sudo transport the redirect
// runs as root.
func writeRemoteFile(ctx context.Context, t api.Transport, path, content string) error {
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	cmd := fmt.Sprintf("echo %s | base64 -d > %s", shellQuote(b64), shellQuote(path))
	res, err := t.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("bootguard: writing %s: transport error: %w", path, err)
	}
	if !res.OK() {
		return fmt.Errorf("bootguard: writing %s failed (exit %d): %s", path, res.ExitCode, res.Stderr)
	}
	return nil
}
