package bootguard

import (
	"strings"
	"testing"
)

// @spec bootguard-confirm
// @ac AC-02
func TestBuildConfirmScript_RHEL_Promotes(t *testing.T) {
	t.Run("bootguard-confirm/AC-02", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorBLS)
	if err != nil {
		t.Fatalf("buildConfirmScript(BLS): %v", err)
	}
	if !strings.Contains(s, "grep -q kensa_bootguard_trial /proc/cmdline") {
		t.Errorf("confirm script must detect the trial via /proc/cmdline; got:\n%s", s)
	}
	if !strings.Contains(s, "grubby --update-kernel=DEFAULT --args=") {
		t.Errorf("confirm script must promote the param onto the default entry; got:\n%s", s)
	}
}

// @spec bootguard-confirm
// @ac AC-03
func TestBuildConfirmScript_RHEL_CleansUpOnFallback(t *testing.T) {
	t.Run("bootguard-confirm/AC-03", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorBLS)
	if err != nil {
		t.Fatalf("buildConfirmScript(BLS): %v", err)
	}
	// The else (fallback) branch removes the trial without promoting.
	if !strings.Contains(s, "else") || !strings.Contains(s, "remove_trial") {
		t.Errorf("confirm script must clean up the trial on fallback; got:\n%s", s)
	}
}

// @spec bootguard-confirm
// @ac AC-04
func TestBuildConfirmScript_RemovesSpecificEntry(t *testing.T) {
	t.Run("bootguard-confirm/AC-04", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorBLS)
	if err != nil {
		t.Fatalf("buildConfirmScript(BLS): %v", err)
	}
	if !strings.Contains(s, "grep -l kensa_bootguard_trial /boot/loader/entries/*.conf") {
		t.Errorf("trial removal must target the sentinel-bearing entry file; got:\n%s", s)
	}
	if strings.Contains(s, "grubby --remove-kernel") {
		t.Errorf("must NOT use grubby --remove-kernel (would drop the default too); got:\n%s", s)
	}
}

// @spec bootguard-confirm
// @ac AC-05
func TestBuildConfirmScript_Ubuntu_Promotes(t *testing.T) {
	t.Run("bootguard-confirm/AC-05", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorLegacy)
	if err != nil {
		t.Fatalf("buildConfirmScript(legacy): %v", err)
	}
	if !strings.Contains(s, "grep -q kensa_bootguard_trial /proc/cmdline") {
		t.Errorf("Ubuntu confirm must detect the trial via /proc/cmdline; got:\n%s", s)
	}
	if !strings.Contains(s, "GRUB_CMDLINE_LINUX") || !strings.Contains(s, "/etc/default/grub") {
		t.Errorf("Ubuntu promote must append the param to GRUB_CMDLINE_LINUX; got:\n%s", s)
	}
	if !strings.Contains(s, "update-grub") {
		t.Errorf("Ubuntu confirm must regenerate via update-grub; got:\n%s", s)
	}
}

// @spec bootguard-confirm
// @ac AC-06
func TestBuildConfirmScript_Ubuntu_CleansUpTrialScript(t *testing.T) {
	t.Run("bootguard-confirm/AC-06", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorLegacy)
	if err != nil {
		t.Fatalf("buildConfirmScript(legacy): %v", err)
	}
	if !strings.Contains(s, "rm -f /etc/grub.d/11_kensa_bootguard") {
		t.Errorf("Ubuntu confirm must remove the trial /etc/grub.d script; got:\n%s", s)
	}
	if !strings.Contains(s, "else") {
		t.Errorf("Ubuntu confirm must have a fallback (else) branch; got:\n%s", s)
	}
}

func TestBuildConfirmScript_UnsupportedFlavor(t *testing.T) {
	if _, err := buildConfirmScript(Flavor("weird")); err == nil {
		t.Error("expected error for unsupported flavor")
	}
}

// @spec bootguard-confirm
// @ac AC-07
func TestBuildConfirmUnit_InvokesViaInterpreter(t *testing.T) {
	t.Run("bootguard-confirm/AC-07", func(t *testing.T) {})
	u := buildConfirmUnit()
	if !strings.Contains(u, "ExecStart=/bin/sh "+confirmScriptPath) {
		t.Errorf("confirm unit must invoke the script via /bin/sh (SELinux var_lib_t cannot be execve'd directly); got:\n%s", u)
	}
	if strings.Contains(u, "ExecStart="+confirmScriptPath) {
		t.Errorf("confirm unit must NOT exec the var_lib script path directly; got:\n%s", u)
	}
}

// @spec bootguard-confirm
// @ac AC-08
func TestConfirmUnit_IsSelfLimiting(t *testing.T) {
	t.Run("bootguard-confirm/AC-08", func(t *testing.T) {})
	u := buildConfirmUnit()
	if !strings.Contains(u, "ConditionPathExists="+trialIDPath) {
		t.Errorf("confirm unit must be guarded by ConditionPathExists on the trial marker; got:\n%s", u)
	}
	for _, fl := range []Flavor{FlavorBLS, FlavorLegacy} {
		s, err := buildConfirmScript(fl)
		if err != nil {
			t.Fatalf("buildConfirmScript(%s): %v", fl, err)
		}
		if !strings.Contains(s, "systemctl disable "+confirmUnitName) {
			t.Errorf("%s confirm script must disable its own unit when done; got:\n%s", fl, s)
		}
		if !strings.Contains(s, "rm -f "+confirmUnitPath) {
			t.Errorf("%s confirm script must remove its own unit file when done; got:\n%s", fl, s)
		}
	}
}

// @spec bootguard-confirm
// @ac AC-09
func TestBuildConfirmScript_RHEL_Promote_BranchesOnOpMode(t *testing.T) {
	t.Run("bootguard-confirm/AC-09", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorBLS)
	if err != nil {
		t.Fatalf("buildConfirmScript(BLS): %v", err)
	}
	if !strings.Contains(s, `"$STATE/op_mode"`) {
		t.Errorf("RHEL confirm must read op_mode; got:\n%s", s)
	}
	if !strings.Contains(s, `grubby --update-kernel=DEFAULT --args=`) {
		t.Errorf("RHEL confirm must have a set branch (--args); got:\n%s", s)
	}
	if !strings.Contains(s, `grubby --update-kernel=DEFAULT --remove-args=`) {
		t.Errorf("RHEL confirm must have a remove branch (--remove-args); got:\n%s", s)
	}
}

// @spec bootguard-confirm
// @ac AC-10
func TestBuildConfirmScript_Ubuntu_Promote_BranchesOnOpMode(t *testing.T) {
	t.Run("bootguard-confirm/AC-10", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorLegacy)
	if err != nil {
		t.Fatalf("buildConfirmScript(legacy): %v", err)
	}
	if !strings.Contains(s, `"$STATE/op_mode"`) {
		t.Errorf("Ubuntu confirm must read op_mode; got:\n%s", s)
	}
	// set branch: sed-append to GRUB_CMDLINE_LINUX
	if !strings.Contains(s, "GRUB_CMDLINE_LINUX=") {
		t.Errorf("Ubuntu confirm must reference GRUB_CMDLINE_LINUX in the set branch; got:\n%s", s)
	}
	// remove branch: sed-strip "$PARAM=<value>" and bare "$PARAM"
	if !strings.Contains(s, `$PARAM=[^ `) || !strings.Contains(s, `\b$PARAM\b`) {
		t.Errorf("Ubuntu confirm must have a remove branch that strips both key=value and bare key; got:\n%s", s)
	}
}
