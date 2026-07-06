// Package bootguard provides the boot-state capture, restore, and one-shot
// trial mechanism behind the grub deadman guard.
//
// A bad kernel parameter set via grub_parameter_set only manifests at the next
// reboot — potentially leaving the host unbootable and unreachable, where an
// in-process rollback cannot help. The guard instead stages the change on a
// throwaway "trial" boot entry armed as a one-shot, leaving the saved default
// untouched: a healthy trial boot is promoted to permanent; a failed one is
// abandoned when the bootloader falls back to the saved default. Recovery is
// therefore the bootloader's job, not any code running on the broken boot.
//
// The package provides DetectFlavor and Capture (read-only); Restore
// (write-back + regenerate); CheckArmable (a fail-closed preflight); and the
// trial/confirm mechanism (ArmOneshot + InstallConfirmUnit). Capture issues
// only read commands and never mutates the host; the mutating paths must run
// over a privileged (Sudo) transport.
package bootguard

import (
	"context"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/shellcapture"
)

// Flavor identifies the bootloader configuration model.
type Flavor string

const (
	// FlavorBLS is BootLoaderSpec (RHEL 8/9/10): per-kernel entries in
	// /boot/loader/entries, managed by grubby.
	FlavorBLS Flavor = "bls"
	// FlavorLegacy is a monolithic grub.cfg (Ubuntu 22.04/24.04/26.04):
	// GRUB_CMDLINE_LINUX in /etc/default/grub regenerated via update-grub.
	FlavorLegacy Flavor = "legacy"
)

const (
	defaultGrubPath = "/etc/default/grub"
	blsEntriesDir   = "/boot/loader/entries"
)

// grubCfgCandidates are the conventional grub.cfg locations, BLS/RHEL first.
var grubCfgCandidates = []string{"/boot/grub2/grub.cfg", "/boot/grub/grub.cfg"}

// Snapshot is a read-only capture of pre-change boot state, sufficient to
// drive a later (gated) Restore.
type Snapshot struct {
	// Flavor is the detected bootloader model.
	Flavor Flavor
	// DefaultGrub is the verbatim contents of /etc/default/grub.
	DefaultGrub string
	// GrubCfgPath is the active grub.cfg path, or "" if none was found.
	GrubCfgPath string
	// BLSEntries maps each BootLoaderSpec entry path to its contents.
	// Populated only when Flavor is FlavorBLS.
	BLSEntries map[string]string
}

// DetectFlavor reports the bootloader model: FlavorBLS when
// /boot/loader/entries exists (RHEL 8/9/10), FlavorLegacy otherwise
// (Ubuntu). Read-only.
func DetectFlavor(ctx context.Context, t api.Transport) (Flavor, error) {
	res, err := t.Run(ctx, fmt.Sprintf("test -d %s", shellQuote(blsEntriesDir)))
	if err != nil {
		return "", fmt.Errorf("bootguard: flavor probe transport error: %w", err)
	}
	if res.ExitCode == 0 {
		return FlavorBLS, nil
	}
	return FlavorLegacy, nil
}

// Capture takes a read-only snapshot of boot state. It issues only read
// commands (test, cat, ls) and never mutates the host.
//
// Capture MUST run over a privileged (Sudo) transport: on hardened RHEL,
// /boot/grub2 and /boot/loader/entries are mode 0700 root, so an
// unprivileged transport cannot read them (and the entry glob expands as
// the unprivileged user). Capture fails closed rather than returning a
// silently-incomplete snapshot — it errors when /etc/default/grub cannot
// be read, and (on BLS) when no entries are readable.
func Capture(ctx context.Context, t api.Transport) (*Snapshot, error) {
	flavor, err := DetectFlavor(ctx, t)
	if err != nil {
		return nil, err
	}

	// base64 (not cat): the transport trims stdout's trailing newline, which
	// dropped /etc/default/grub's final \n so Restore rewrote it one byte short
	// (#247). base64 round-trips the exact bytes. Restore already writes via base64.
	dg, err := t.Run(ctx, fmt.Sprintf("base64 %s", shellQuote(defaultGrubPath)))
	if err != nil {
		return nil, fmt.Errorf("bootguard: reading %s: transport error: %w", defaultGrubPath, err)
	}
	if !dg.OK() {
		return nil, fmt.Errorf("bootguard: cannot read %s (exit %d): %s",
			defaultGrubPath, dg.ExitCode, strings.TrimSpace(dg.Stderr))
	}
	defaultGrubContent, decErr := shellcapture.DecodeContent(dg.Stdout)
	if decErr != nil {
		return nil, fmt.Errorf("bootguard: decoding %s: %w", defaultGrubPath, decErr)
	}

	snap := &Snapshot{
		Flavor:      flavor,
		DefaultGrub: defaultGrubContent,
		GrubCfgPath: detectGrubCfgPath(ctx, t),
	}

	if flavor == FlavorBLS {
		entries, err := captureBLSEntries(ctx, t)
		if err != nil {
			return nil, err
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("bootguard: BLS host but no readable entries under %s — incomplete capture (Capture requires a privileged/sudo transport to read the root-only boot directories)", blsEntriesDir)
		}
		snap.BLSEntries = entries
	}

	return snap, nil
}

// detectGrubCfgPath returns the first existing grub.cfg candidate, or "".
func detectGrubCfgPath(ctx context.Context, t api.Transport) string {
	for _, p := range grubCfgCandidates {
		res, err := t.Run(ctx, fmt.Sprintf("test -f %s", shellQuote(p)))
		if err == nil && res.ExitCode == 0 {
			return p
		}
	}
	return ""
}

// captureBLSEntries reads every BootLoaderSpec entry file under
// /boot/loader/entries, keyed by path. Read-only.
func captureBLSEntries(ctx context.Context, t api.Transport) (map[string]string, error) {
	listing, err := t.Run(ctx, fmt.Sprintf("ls -1 %s/*.conf 2>/dev/null || true", blsEntriesDir))
	if err != nil {
		return nil, fmt.Errorf("bootguard: listing BLS entries: transport error: %w", err)
	}
	entries := make(map[string]string)
	for _, path := range strings.Fields(listing.Stdout) {
		// base64 (not cat) so Restore rewrites each BLS entry byte-perfect (#247).
		res, err := t.Run(ctx, fmt.Sprintf("base64 %s", shellQuote(path)))
		if err != nil {
			return nil, fmt.Errorf("bootguard: reading BLS entry %s: transport error: %w", path, err)
		}
		if res.OK() {
			content, decErr := shellcapture.DecodeContent(res.Stdout)
			if decErr != nil {
				return nil, fmt.Errorf("bootguard: decoding BLS entry %s: %w", path, decErr)
			}
			entries[path] = content
		}
	}
	return entries, nil
}

// shellQuote wraps s in single quotes for safe shell inclusion.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
