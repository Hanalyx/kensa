package rule

import (
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa-go/api"
)

// LintWarning is an advisory finding from [Lint]. Lint warnings identify
// likely effective-vs-static configuration check defects but do not
// constitute schema violations — they require human judgement.
//
// A warning may be suppressed by adding a `# kensa-validate: allow-static-check`
// annotation with a justification to the rule YAML. Suppression is not
// yet parsed by this package; the annotation is a convention for
// documentation purposes.
type LintWarning struct {
	// RuleID is the rule that triggered the warning.
	RuleID string
	// ImplIndex is the zero-based index into rule.Implementations.
	ImplIndex int
	// Path identifies the path or check element that triggered the warning.
	Path string
	// Code is a short machine-readable warning identifier.
	Code string
	// Msg is the human-readable explanation.
	Msg string
}

// String formats the warning for display.
func (w LintWarning) String() string {
	return fmt.Sprintf("[%s] rule %s impl[%d] %s: %s", w.Code, w.RuleID, w.ImplIndex, w.Path, w.Msg)
}

// Lint runs the effective-vs-static heuristics on rule and returns a
// (possibly empty) slice of [LintWarning] values.
//
// Heuristics from docs/KENSA_GO_DAY1_PLAN.md §7.5:
//
//   - (W001) config_value on /etc/ssh/sshd_config without a sibling
//     sshd_config_d-gated implementation. Systems with drop-in support
//     may have effective settings that differ from the base file.
//
//   - (W002) config_value on /etc/sysctl.conf or /etc/sysctl.d/*.
//     Use sysctl_value check method instead — it reads the live kernel
//     value and is not fooled by file-level overrides.
//
//   - (W003) config_value or file_content_match on /etc/pam.d/* without
//     the implementation being gated on the authselect capability.
//     authselect may override PAM files, making static reads unreliable.
//
//   - (W004) config_value or file_content_match on /etc/fstab. Use
//     mount_option check method instead — it reads effective mount state
//     via the kernel rather than the configuration file.
//
//   - (W005) config_value on /etc/selinux/config. Use selinux_state or
//     selinux_boolean check methods — they read runtime enforcement state,
//     which may differ from the config file value.
func Lint(rule *api.Rule) []LintWarning {
	hasSshdDropinImpl := hasSshdDropinGatedImpl(rule)

	var warns []LintWarning
	for i, impl := range rule.Implementations {
		warns = append(warns, lintChecks(rule.ID, i, impl, hasSshdDropinImpl)...)
	}
	return warns
}

// hasSshdDropinGatedImpl returns true when the rule has at least one
// implementation whose when gate includes sshd_config_d.
func hasSshdDropinGatedImpl(rule *api.Rule) bool {
	for _, impl := range rule.Implementations {
		caps := collectCapabilityRefs(impl.When)
		for _, c := range caps {
			if c == "sshd_config_d" {
				return true
			}
		}
	}
	return false
}

// lintChecks lints the check(s) in a single implementation.
func lintChecks(ruleID string, implIdx int, impl api.Implementation, hasSshdDropin bool) []LintWarning {
	return lintCheck(ruleID, implIdx, impl, impl.Check, hasSshdDropin)
}

// lintCheck recursively lints a check (handling multi-check AND lists).
func lintCheck(ruleID string, implIdx int, impl api.Implementation, check api.Check, hasSshdDropin bool) []LintWarning {
	var warns []LintWarning

	if len(check.Checks) > 0 {
		for _, c := range check.Checks {
			warns = append(warns, lintCheck(ruleID, implIdx, impl, c, hasSshdDropin)...)
		}
		return warns
	}

	path, _ := check.Params["path"].(string)

	switch check.Method {
	case "config_value":
		warns = append(warns, lintConfigValue(ruleID, implIdx, path, impl.When, hasSshdDropin)...)

	case "file_content_match", "file_content_no_match":
		warns = append(warns, lintFileContentMatch(ruleID, implIdx, path, impl.When)...)
	}

	return warns
}

func lintConfigValue(ruleID string, implIdx int, path string, when interface{}, hasSshdDropin bool) []LintWarning {
	var warns []LintWarning

	// W001: /etc/ssh/sshd_config without drop-in sibling.
	if path == "/etc/ssh/sshd_config" && !hasSshdDropin {
		warns = append(warns, LintWarning{
			RuleID:    ruleID,
			ImplIndex: implIdx,
			Path:      path,
			Code:      "W001",
			Msg: "config_value check on /etc/ssh/sshd_config without a sibling implementation " +
				"gated on sshd_config_d; effective config may differ when drop-ins are present. " +
				"Add a second implementation with when:sshd_config_d that reads from /etc/ssh/sshd_config.d, " +
				"or suppress with '# kensa-validate: allow-static-check' plus a justification.",
		})
	}

	// W002: /etc/sysctl.conf or /etc/sysctl.d/.
	if path == "/etc/sysctl.conf" || strings.HasPrefix(path, "/etc/sysctl.d/") {
		warns = append(warns, LintWarning{
			RuleID:    ruleID,
			ImplIndex: implIdx,
			Path:      path,
			Code:      "W002",
			Msg: fmt.Sprintf("config_value check on %q reads from a sysctl config file; "+
				"use sysctl_value check method instead to read the live kernel parameter value, "+
				"which is authoritative regardless of file-level overrides.", path),
		})
	}

	// W005: /etc/selinux/config.
	if path == "/etc/selinux/config" {
		warns = append(warns, LintWarning{
			RuleID:    ruleID,
			ImplIndex: implIdx,
			Path:      path,
			Code:      "W005",
			Msg: "config_value check on /etc/selinux/config reads the static config file; " +
				"use selinux_state or selinux_boolean check method to read the runtime enforcement " +
				"state, which may differ from the file value (e.g., when setenforce has been called).",
		})
	}

	// W003: /etc/pam.d/* without authselect gate.
	if strings.HasPrefix(path, "/etc/pam.d/") {
		caps := collectCapabilityRefs(when)
		hasAuthselect := false
		for _, c := range caps {
			if c == "authselect" {
				hasAuthselect = true
				break
			}
		}
		if !hasAuthselect {
			warns = append(warns, LintWarning{
				RuleID:    ruleID,
				ImplIndex: implIdx,
				Path:      path,
				Code:      "W003",
				Msg: fmt.Sprintf("config_value check on %q reads a PAM config file directly; "+
					"authselect may override PAM stack files, making static reads unreliable. "+
					"Gate this implementation on the authselect capability or add an authselect-gated "+
					"sibling implementation, or suppress with '# kensa-validate: allow-static-check'.", path),
			})
		}
	}

	return warns
}

func lintFileContentMatch(ruleID string, implIdx int, path string, when interface{}) []LintWarning {
	var warns []LintWarning

	// W004: /etc/fstab.
	if path == "/etc/fstab" {
		warns = append(warns, LintWarning{
			RuleID:    ruleID,
			ImplIndex: implIdx,
			Path:      path,
			Code:      "W004",
			Msg: "file_content_match check on /etc/fstab reads the static fstab file; " +
				"effective mount options may differ (bind mounts, systemd.mount units, etc.). " +
				"Use mount_option check method to read the kernel's effective mount state " +
				"via /proc/mounts.",
		})
	}

	// W003: /etc/pam.d/* without authselect gate.
	if strings.HasPrefix(path, "/etc/pam.d/") {
		caps := collectCapabilityRefs(when)
		hasAuthselect := false
		for _, c := range caps {
			if c == "authselect" {
				hasAuthselect = true
				break
			}
		}
		if !hasAuthselect {
			warns = append(warns, LintWarning{
				RuleID:    ruleID,
				ImplIndex: implIdx,
				Path:      path,
				Code:      "W003",
				Msg: fmt.Sprintf("file_content_match check on %q reads a PAM config file directly; "+
					"authselect may override PAM stack files, making static reads unreliable. "+
					"Gate this implementation on the authselect capability, or suppress with "+
					"'# kensa-validate: allow-static-check'.", path),
			})
		}
	}

	return warns
}
