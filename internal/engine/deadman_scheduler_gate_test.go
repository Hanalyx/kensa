package engine

import "testing"

// rebootRequiredMechanisms are the mechanisms whose effect does not exist
// until the host reboots. Each entry records why, because the reason is what a
// future reader has to re-check rather than the membership.
var rebootRequiredMechanisms = map[string]string{
	"grub_parameter_set":    "a kernel command-line argument takes effect at the next boot",
	"grub_parameter_remove": "same, in the inverse direction",
	"mount_option_set":      "fstab is the persistence layer; the option is live only after a remount or reboot",
	"kernel_module_disable": "a blacklist prevents the next load; an already-loaded module survives until reboot",
	"audit_rule_set":        "on an immutable audit config (enabled=2) the rule is staged and loads at boot",
}

// TestDeadmanIsNotUsedForRebootRequiredChanges enforces deadman-timer spec
// C-11, which is a gate rather than a behavior and so cannot be checked by
// exercising the deadman itself.
//
// The deadman is a TIME-WINDOW instrument. It arms before Apply and is
// canceled at Commit, so it covers seconds, and it is armed only for
// mechanisms that can cost Kensa its control channel. A change that only takes
// effect at the next boot cannot brick the channel inside that window, and the
// window will have expired long before the operator reboots — the engine
// already cancels the timer for staged applies for exactly this reason.
// Reboot-scoped safety belongs to internal/bootguard, whose one-shot trial
// entry and saved-default fallback are keyed to the boot rather than a clock.
//
// This matters to the SCHEDULER choice, which is why it is a gate and not
// merely a design note. The shell path arms systemd-run for reliability and
// at(1) as the backstop across a reboot, because a systemd-run transient unit
// lives in tmpfs and a power cycle erases it. On a host carrying only
// systemd-run there is therefore no post-reboot net at all. That is acceptable
// while nothing reboot-required is control-channel-sensitive, and stops being
// acceptable the moment one is.
//
// So if this test fails, do not relax it. Either the mechanism does not
// actually need a reboot — fix the map above and say why — or the scheduler
// choice in internal/engine/deadman must be revisited before the change lands,
// and the at(1)-absent case closed rather than documented.
//
// @spec deadman-timer
// @ac AC-16
func TestDeadmanIsNotUsedForRebootRequiredChanges(t *testing.T) {
	t.Run("deadman-timer/AC-16", func(t *testing.T) {})

	for mech, why := range rebootRequiredMechanisms {
		if _, known := controlChannelMechanisms[mech]; !known {
			t.Errorf("%s is listed as reboot-required but is not a known mechanism; "+
				"if it was renamed or removed, update this map", mech)
			continue
		}
		if controlChannelMechanisms[mech] {
			t.Errorf("%s is marked control-channel-sensitive, so the deadman now arms "+
				"for it — but %s. A time window cannot guard a change that lands at the "+
				"next boot, and on a host without at(1) there is no post-reboot net at "+
				"all. See deadman-timer spec C-11: revisit the scheduler choice before "+
				"landing this, or use internal/bootguard, which is keyed to the boot.",
				mech, why)
		}
	}
}
