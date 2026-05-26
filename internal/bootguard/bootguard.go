// Package bootguard provides the boot-state capture that underpins the
// grub deadman guard (see docs/roadmap/GRUB-DEADMAN-GUARD-DESIGN.md).
//
// A bad kernel parameter set via grub_parameter_set only manifests at the
// next reboot — potentially leaving the host unbootable and unreachable, so
// the in-window deadman cannot help. The eventual guard captures boot state
// before applying, then relies on a bootloader-level boot-success mechanism
// to revert on a failed boot.
//
// This package currently implements DETECTION and read-only CAPTURE only.
// Restore (write-back + regenerate) and the boot-resident success/revert
// mechanism are separate, gated increments pending real-host reboot testing
// and a founder-authored failure-mode analysis. Capture issues only
// read commands and never mutates the host.
package bootguard

import (
	"context"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa/api"
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
// commands (test, cat, ls) and never mutates the host. It returns an error
// rather than a partial snapshot when /etc/default/grub cannot be read.
func Capture(ctx context.Context, t api.Transport) (*Snapshot, error) {
	flavor, err := DetectFlavor(ctx, t)
	if err != nil {
		return nil, err
	}

	dg, err := t.Run(ctx, fmt.Sprintf("cat %s", shellQuote(defaultGrubPath)))
	if err != nil {
		return nil, fmt.Errorf("bootguard: reading %s: transport error: %w", defaultGrubPath, err)
	}
	if !dg.OK() {
		return nil, fmt.Errorf("bootguard: cannot read %s (exit %d): %s",
			defaultGrubPath, dg.ExitCode, strings.TrimSpace(dg.Stderr))
	}

	snap := &Snapshot{
		Flavor:      flavor,
		DefaultGrub: dg.Stdout,
		GrubCfgPath: detectGrubCfgPath(ctx, t),
	}

	if flavor == FlavorBLS {
		entries, err := captureBLSEntries(ctx, t)
		if err != nil {
			return nil, err
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
		res, err := t.Run(ctx, fmt.Sprintf("cat %s", shellQuote(path)))
		if err != nil {
			return nil, fmt.Errorf("bootguard: reading BLS entry %s: transport error: %w", path, err)
		}
		if res.OK() {
			entries[path] = res.Stdout
		}
	}
	return entries, nil
}

// shellQuote wraps s in single quotes for safe shell inclusion.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
