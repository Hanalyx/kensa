package bootguard_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/bootguard"
	"github.com/Hanalyx/kensa/internal/engine"
)

// mutatingTokens are shell fragments that would indicate a write/mutation.
// Capture must issue none of them.
var mutatingTokens = []string{"sed", "printf", "tee", ">", "grub2-mkconfig", "grub-mkconfig", "update-grub", "grubby", "rm ", "cp ", "mv ", "grub2-editenv", "grub-editenv"}

// @spec bootguard-capture
// @ac AC-01
func TestDetectFlavor_BLS(t *testing.T) {
	t.Run("bootguard-capture/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results[`test -d '/boot/loader/entries'`] = &api.CommandResult{ExitCode: 0}
	f, err := bootguard.DetectFlavor(context.Background(), tp)
	if err != nil {
		t.Fatalf("DetectFlavor: %v", err)
	}
	if f != bootguard.FlavorBLS {
		t.Errorf("got %q, want %q", f, bootguard.FlavorBLS)
	}
}

// @spec bootguard-capture
// @ac AC-02
func TestDetectFlavor_Legacy(t *testing.T) {
	t.Run("bootguard-capture/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results[`test -d '/boot/loader/entries'`] = &api.CommandResult{ExitCode: 1}
	f, err := bootguard.DetectFlavor(context.Background(), tp)
	if err != nil {
		t.Fatalf("DetectFlavor: %v", err)
	}
	if f != bootguard.FlavorLegacy {
		t.Errorf("got %q, want %q", f, bootguard.FlavorLegacy)
	}
}

// @spec bootguard-capture
// @ac AC-03
func TestCapture_RecordsDefaultGrubAndCfgPath(t *testing.T) {
	t.Run("bootguard-capture/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results[`test -d '/boot/loader/entries'`] = &api.CommandResult{ExitCode: 1} // legacy
	tp.Results[`base64 '/etc/default/grub'`] = &api.CommandResult{Stdout: base64.StdEncoding.EncodeToString([]byte("GRUB_CMDLINE_LINUX=\"quiet\"\n"))}
	tp.Results[`test -f '/boot/grub2/grub.cfg'`] = &api.CommandResult{ExitCode: 1}
	tp.Results[`test -f '/boot/grub/grub.cfg'`] = &api.CommandResult{ExitCode: 0}
	snap, err := bootguard.Capture(context.Background(), tp)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if snap.Flavor != bootguard.FlavorLegacy {
		t.Errorf("flavor=%q, want legacy", snap.Flavor)
	}
	if !strings.Contains(snap.DefaultGrub, "GRUB_CMDLINE_LINUX") {
		t.Errorf("DefaultGrub not captured: %q", snap.DefaultGrub)
	}
	if snap.GrubCfgPath != "/boot/grub/grub.cfg" {
		t.Errorf("GrubCfgPath=%q, want /boot/grub/grub.cfg", snap.GrubCfgPath)
	}
}

// @spec bootguard-capture
// @ac AC-04
func TestCapture_BLS_RecordsEntries(t *testing.T) {
	t.Run("bootguard-capture/AC-04", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results[`test -d '/boot/loader/entries'`] = &api.CommandResult{ExitCode: 0} // BLS
	tp.Results[`base64 '/etc/default/grub'`] = &api.CommandResult{Stdout: base64.StdEncoding.EncodeToString([]byte("GRUB_CMDLINE_LINUX=\"quiet\"\n"))}
	// /boot/grub2/grub.cfg defaults to exit 0 (BLS/RHEL convention).
	tp.Results[`ls -1 /boot/loader/entries/*.conf 2>/dev/null || true`] = &api.CommandResult{
		Stdout: "/boot/loader/entries/abc-5.14.0.conf\n/boot/loader/entries/abc-5.14.0-rescue.conf\n",
	}
	tp.Results[`base64 '/boot/loader/entries/abc-5.14.0.conf'`] = &api.CommandResult{Stdout: base64.StdEncoding.EncodeToString([]byte("options root=/dev/vda1 ro quiet\n"))}
	tp.Results[`base64 '/boot/loader/entries/abc-5.14.0-rescue.conf'`] = &api.CommandResult{Stdout: base64.StdEncoding.EncodeToString([]byte("options root=/dev/vda1 ro\n"))}
	snap, err := bootguard.Capture(context.Background(), tp)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if snap.Flavor != bootguard.FlavorBLS {
		t.Fatalf("flavor=%q, want bls", snap.Flavor)
	}
	if len(snap.BLSEntries) != 2 {
		t.Fatalf("want 2 BLS entries, got %d: %v", len(snap.BLSEntries), snap.BLSEntries)
	}
	if got := snap.BLSEntries["/boot/loader/entries/abc-5.14.0.conf"]; !strings.Contains(got, "options root=") {
		t.Errorf("entry contents not captured: %q", got)
	}
}

// @spec bootguard-capture
// @ac AC-05
func TestCapture_IsReadOnly(t *testing.T) {
	t.Run("bootguard-capture/AC-05", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results[`test -d '/boot/loader/entries'`] = &api.CommandResult{ExitCode: 0} // BLS — exercises the most commands
	tp.Results[`base64 '/etc/default/grub'`] = &api.CommandResult{Stdout: base64.StdEncoding.EncodeToString([]byte("GRUB_CMDLINE_LINUX=\"quiet\"\n"))}
	tp.Results[`ls -1 /boot/loader/entries/*.conf 2>/dev/null || true`] = &api.CommandResult{
		Stdout: "/boot/loader/entries/abc.conf\n",
	}
	tp.Results[`base64 '/boot/loader/entries/abc.conf'`] = &api.CommandResult{Stdout: base64.StdEncoding.EncodeToString([]byte("options ro\n"))}
	if _, err := bootguard.Capture(context.Background(), tp); err != nil {
		t.Fatalf("Capture: %v", err)
	}
	for _, cmd := range tp.Runs {
		// Strip read-only stderr redirects so they don't false-positive
		// against the ">" write-redirect token.
		clean := strings.ReplaceAll(cmd, "2>/dev/null", "")
		clean = strings.ReplaceAll(clean, "2>&1", "")
		for _, tok := range mutatingTokens {
			if strings.Contains(clean, tok) {
				t.Errorf("Capture issued a mutating command %q (token %q)", cmd, tok)
			}
		}
	}
}

// @spec bootguard-capture
// @ac AC-06
func TestCapture_ErrorWhenDefaultGrubUnreadable(t *testing.T) {
	t.Run("bootguard-capture/AC-06", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results[`test -d '/boot/loader/entries'`] = &api.CommandResult{ExitCode: 1}
	tp.Results[`base64 '/etc/default/grub'`] = &api.CommandResult{
		ExitCode: 1,
		Stderr:   "cat: /etc/default/grub: No such file or directory",
	}
	if _, err := bootguard.Capture(context.Background(), tp); err == nil {
		t.Fatal("expected error when /etc/default/grub is unreadable")
	}
}

// @spec bootguard-capture
// @ac AC-07
func TestCapture_BLS_FailsClosedOnNoEntries(t *testing.T) {
	t.Run("bootguard-capture/AC-07", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results[`test -d '/boot/loader/entries'`] = &api.CommandResult{ExitCode: 0} // BLS
	tp.Results[`base64 '/etc/default/grub'`] = &api.CommandResult{Stdout: base64.StdEncoding.EncodeToString([]byte("GRUB_CMDLINE_LINUX=\"quiet\"\n"))}
	// No readable entries (e.g. unprivileged transport on a 0700 boot dir).
	tp.Results[`ls -1 /boot/loader/entries/*.conf 2>/dev/null || true`] = &api.CommandResult{Stdout: ""}
	if _, err := bootguard.Capture(context.Background(), tp); err == nil {
		t.Fatal("expected fail-closed error on BLS host with no readable entries")
	}
}
