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

func TestStripKeyFromLinuxLine_StripsKeyValueAndBareToken(t *testing.T) {
	in := "\tlinux\t/vmlinuz-X ro audit=1 systemd.confirm_spawn pti=on quiet"
	out := stripKeyFromLinuxLine(in, "systemd.confirm_spawn")
	if strings.Contains(out, "systemd.confirm_spawn") {
		t.Errorf("expected bare key removed; got %q", out)
	}
	out2 := stripKeyFromLinuxLine(in, "audit")
	if strings.Contains(out2, "audit=1") {
		t.Errorf("expected key=value removed; got %q", out2)
	}
	// Positional preservation: "linux" and the kernel path must stay.
	for _, want := range []string{"linux", "/vmlinuz-X"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q preserved; got %q", want, out)
		}
	}
	// Leading whitespace preserved.
	if !strings.HasPrefix(out, "\tlinux") {
		t.Errorf("expected leading tab preserved; got %q", out)
	}
}

func TestBuildUbuntuTrialEntryRemove_StripsKeyAndAppendsSentinel(t *testing.T) {
	out := buildUbuntuTrialEntryRemove(sampleBlock, "ro")
	// The key must be gone from the linux line.
	for _, ln := range strings.Split(out, "\n") {
		trim := strings.TrimSpace(ln)
		if strings.HasPrefix(trim, "linux ") || strings.HasPrefix(trim, "linux\t") {
			if strings.Contains(" "+trim+" ", " ro ") {
				t.Errorf("expected bare 'ro' stripped from linux line; got %q", trim)
			}
			if !strings.Contains(trim, trialSentinel) {
				t.Errorf("expected sentinel appended to linux line; got %q", trim)
			}
		}
	}
	if !strings.Contains(out, "menuentry '"+trialTitle+"'") {
		t.Errorf("expected retitled menuentry; got:\n%s", out)
	}
}
