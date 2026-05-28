package grubparameterremove_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/grubparameterremove"
)

// These mirror the unexported probe commands in internal/bootguard/gate.go. If
// they drift, the armable-path test below stops seeing an armable host and
// fails loudly — which is the intended coupling alarm.
const (
	uefiProbe   = `test -d /sys/firmware/efi`
	ostreeProbe = `test -e /run/ostree-booted`
	encProbe    = `t=$(findmnt -no SOURCE /boot 2>/dev/null || findmnt -no SOURCE / 2>/dev/null); test -n "$t" && lsblk -nso TYPE "$t" 2>/dev/null | grep -qx crypt`
)

// armableBLS programs a FakeTransport to look like a plain BIOS/GRUB/BLS host:
// uefi/ostree/encrypted probes fail (exit 1), grub is present (default exit 0),
// /boot/loader/entries exists (default exit 0 → BLS), grubby reports a default
// kernel, and the sentinel-grep that locates the freshly-created trial .conf
// (step 2 of armOneshotRemoveBLS) returns a stub path.
func armableBLS() *engine.FakeTransport {
	tp := engine.NewFakeTransport()
	tp.Results[uefiProbe] = &api.CommandResult{ExitCode: 1}
	tp.Results[ostreeProbe] = &api.CommandResult{ExitCode: 1}
	tp.Results[encProbe] = &api.CommandResult{ExitCode: 1}
	tp.Results["grubby --default-kernel"] = &api.CommandResult{Stdout: "/boot/vmlinuz-test\n"}
	tp.Results["grep -l 'kensa_bootguard_trial' /boot/loader/entries/*.conf 2>/dev/null | head -1"] =
		&api.CommandResult{Stdout: "/boot/loader/entries/trial.conf\n"}
	return tp
}

func anyRunContains(runs []string, subs ...string) bool {
	for _, r := range runs {
		all := true
		for _, s := range subs {
			if !strings.Contains(r, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// @spec handler-grub-parameter-remove
// @ac AC-01
func TestApply_RefusesOffAllowlistKey(t *testing.T) {
	t.Run("handler-grub-parameter-remove/AC-01", func(t *testing.T) {})
	tp := armableBLS()
	h := grubparameterremove.New()
	_, err := h.Apply(context.Background(), tp, api.Params{"key": "evil_key"}, nil)
	if err == nil {
		t.Fatal("expected an error for an off-allowlist key")
	}
	if len(tp.Runs) != 0 {
		t.Errorf("off-allowlist key must be refused before any host command; runs=%v", tp.Runs)
	}
}

// @spec handler-grub-parameter-remove
// @ac AC-02
func TestDecodeParams_RejectsInvalid(t *testing.T) {
	t.Run("handler-grub-parameter-remove/AC-02", func(t *testing.T) {})
	h := grubparameterremove.New()
	cases := []struct {
		name   string
		params api.Params
	}{
		{"nil params", nil},
		{"missing key", api.Params{}},
		{"empty key", api.Params{"key": ""}},
		{"non-string key", api.Params{"key": 42}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tp := engine.NewFakeTransport()
			if _, err := h.Apply(context.Background(), tp, tc.params, nil); err == nil {
				t.Errorf("expected error for %q", tc.name)
			}
			if len(tp.Runs) != 0 {
				t.Errorf("expected no commands run on invalid params; runs=%v", tp.Runs)
			}
		})
	}
}

// @spec handler-grub-parameter-remove
// @ac AC-03
func TestApply_RefusesNonArmableHost(t *testing.T) {
	t.Run("handler-grub-parameter-remove/AC-03", func(t *testing.T) {})
	// A default fake answers every probe with exit 0 → looks like a UEFI +
	// ostree + encrypted host → CheckArmable refuses.
	tp := engine.NewFakeTransport()
	h := grubparameterremove.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"key": "systemd.confirm_spawn"}, nil)
	if err != nil {
		t.Fatalf("Apply returned error (want StepResult Success=false): %v", err)
	}
	if res.Success {
		t.Errorf("expected Success=false on a non-armable host; detail=%s", res.Detail)
	}
	if anyRunContains(tp.Runs, "grubby --add-kernel") || anyRunContains(tp.Runs, "kensa-bootguard-confirm") {
		t.Errorf("must not arm on a non-armable host; runs=%v", tp.Runs)
	}
}

// @spec handler-grub-parameter-remove
// @ac AC-04
func TestApply_ArmsRemovalNotSed(t *testing.T) {
	t.Run("handler-grub-parameter-remove/AC-04", func(t *testing.T) {})
	tp := armableBLS()
	h := grubparameterremove.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"key": "systemd.confirm_spawn"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success=true on an armable host; detail=%s", res.Detail)
	}
	if !strings.Contains(res.Detail, "REMOVAL") || !strings.Contains(res.Detail, "PENDING") {
		t.Errorf("Detail must report a pending removal; got %q", res.Detail)
	}
	if !anyRunContains(tp.Runs, "kensa-bootguard-confirm") {
		t.Errorf("expected the confirm unit to be installed; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, "grubby --add-kernel", "--remove-args=", "systemd.confirm_spawn", "kensa_bootguard_trial") {
		t.Errorf("expected a one-shot trial entry that removes the key + carries the sentinel; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, "grub2-reboot") {
		t.Errorf("expected the one-shot to be armed (grub2-reboot); runs=%v", tp.Runs)
	}
	// Must NOT use the legacy sed-on-default-grub + mkconfig path. ("-o " is the
	// run flag; "grub2-mkconfig" alone also appears in the CheckArmable probe
	// `command -v grub2-mkconfig` and is not a regression.)
	if anyRunContains(tp.Runs, "GRUB_CMDLINE_LINUX") || anyRunContains(tp.Runs, "grub2-mkconfig -o") {
		t.Errorf("Apply must NOT directly edit GRUB_CMDLINE_LINUX or run grub2-mkconfig -o; runs=%v", tp.Runs)
	}
}

// @spec handler-grub-parameter-remove
// @ac AC-05
// @spec handler-interface
// @ac AC-05
func TestHandler_NonCapturable(t *testing.T) {
	t.Run("handler-grub-parameter-remove/AC-05", func(t *testing.T) {})
	t.Run("handler-interface/AC-05", func(t *testing.T) {})
	h := grubparameterremove.New()
	if h.Capturable() {
		t.Error("Capturable() must be false for grub_parameter_remove")
	}
	if _, ok := interface{}(h).(api.CombinedHandler); ok {
		t.Error("non-capturable handler must not satisfy CombinedHandler")
	}
}
