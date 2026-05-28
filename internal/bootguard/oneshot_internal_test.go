package bootguard

import (
	"strings"
	"testing"
)

const sampleBlock = `menuentry 'Ubuntu' --class ubuntu $menuentry_id_option 'gnulinux-simple-uuid' {
	recordfail
	search --no-floppy --fs-uuid --set=root 1a3e85dc
	linux	/vmlinuz-5.15.0-179-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro
	initrd	/initrd.img-5.15.0-179-generic
}`

// @spec bootguard-oneshot
// @ac AC-05
func TestBuildUbuntuTrialEntry(t *testing.T) {
	t.Run("bootguard-oneshot/AC-05", func(t *testing.T) {})
	out := buildUbuntuTrialEntry(sampleBlock, "audit=1")

	if !strings.Contains(out, "menuentry 'kensa-bootguard-trial' {") {
		t.Errorf("trial must be retitled; got:\n%s", out)
	}
	// linux line keeps the original args and gains the param + sentinel.
	if !strings.Contains(out, "root=/dev/mapper/ubuntu--vg-ubuntu--lv ro audit=1 kensa_bootguard_trial") {
		t.Errorf("linux line must append param+sentinel after the originals; got:\n%s", out)
	}
	// Boot-critical lines preserved verbatim.
	if !strings.Contains(out, "search --no-floppy --fs-uuid --set=root 1a3e85dc") {
		t.Errorf("search/set-root must be preserved; got:\n%s", out)
	}
	if !strings.Contains(out, "initrd\t/initrd.img-5.15.0-179-generic") {
		t.Errorf("initrd must be preserved; got:\n%s", out)
	}
}

// @spec bootguard-oneshot
// @ac AC-05
func TestExtractDefaultMenuentry(t *testing.T) {
	t.Run("bootguard-oneshot/AC-05", func(t *testing.T) {})
	cfg := "set timeout=5\n" + sampleBlock + "\nsubmenu 'x' {\n  menuentry 'y' { linux /z }\n}\n"
	block, err := extractDefaultMenuentry(cfg)
	if err != nil {
		t.Fatalf("extractDefaultMenuentry: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(block), "menuentry 'Ubuntu'") {
		t.Errorf("expected the first top-level menuentry; got:\n%s", block)
	}
	if strings.Contains(block, "submenu") {
		t.Errorf("extraction must stop at the first menuentry's close, not swallow the submenu; got:\n%s", block)
	}
	if _, err := extractDefaultMenuentry("no menuentry here"); err == nil {
		t.Error("expected error when no menuentry is present")
	}
}

// @spec bootguard-oneshot
// @ac AC-07
func TestUbuntuTrialScript_OrdersAfter10Linux(t *testing.T) {
	t.Run("bootguard-oneshot/AC-07", func(t *testing.T) {})
	base := ubuntuTrialScript[strings.LastIndex(ubuntuTrialScript, "/")+1:]
	// update-grub runs /etc/grub.d scripts in LC_ALL=C sorted order. The trial
	// script must sort AFTER 10_linux so the real default stays menu index 0;
	// with GRUB_DEFAULT=0 a failed trial then falls back to the real default,
	// not to the trial (which would boot-loop).
	if base <= "10_linux" {
		t.Errorf("trial script %q must sort after 10_linux (failed-trial fallback safety); base=%q", ubuntuTrialScript, base)
	}
}
