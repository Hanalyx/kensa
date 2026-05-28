package bootguard

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// allowedParams is the set of kernel command-line parameter KEYS the boot guard
// will arm for. It is exactly the set the rule corpus uses for grub remediations
// (CIS/STIG kernel hardening) plus the single key the corpus removes
// (systemd.confirm_spawn). Anything outside this set is refused BEFORE arming,
// so a typo, an exotic param, or a bad rule can never reach a real (trial) boot
// — the deadman fallback is a second net, not the only one.
//
// Extend this list (under review) when a new compliance param is added. Keys are
// matched exactly: the bare param name, never a value.
var allowedParams = map[string]bool{
	"audit":                 true, // grub-audit-enabled
	"audit_backlog_limit":   true, // grub-audit-backlog
	"init_on_alloc":         true, // grub-page-alloc-shuffle
	"page_poison":           true, // grub-page-poison
	"pti":                   true, // grub-processor-mitigations
	"slub_debug":            true, // grub-slub-debug
	"vsyscall":              true, // grub-vsyscall-none
	"systemd.confirm_spawn": true, // interactive-boot-disabled (grub_parameter_remove)
}

// ParamAllowed reports whether key is on the boot-guard allowlist.
func ParamAllowed(key string) bool { return allowedParams[key] }

// AllowedParams returns the allowlisted keys, sorted, for diagnostics and the
// refusal message.
func AllowedParams() []string {
	keys := make([]string, 0, len(allowedParams))
	for k := range allowedParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CheckParamArmable is the per-param preflight gate: the key must be non-empty
// and on the allowlist. It returns a clear error naming the key when it is not.
// Host-level arm-ability (GRUB present, not UEFI/ostree/encrypted /boot) is a
// separate gate — see CheckArmable. BOTH must pass before ArmOneshot.
func CheckParamArmable(key string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("bootguard: empty param key")
	}
	if !ParamAllowed(key) {
		return fmt.Errorf("bootguard: param %q is not on the boot-guard allowlist %v; refusing to arm "+
			"(add it under review if it is a legitimate compliance param)", key, AllowedParams())
	}
	return nil
}
