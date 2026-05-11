package engine

import (
	"fmt"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/handler"
)

// preflight validates the transaction before any host interaction.
// Failures here abort the run before capture so no host state is
// observed or modified.
//
// Per engine-transaction spec C-03 and AC-11, a transaction declared
// transactional:true that contains any non-capturable mechanism is
// rejected here — the schema validator should have caught it earlier,
// but we re-enforce at runtime as a safety belt.
func (e *Engine) preflight(txn *api.Transaction) error {
	if len(txn.Steps) == 0 {
		return fmt.Errorf("preflight: transaction has no steps")
	}

	for _, step := range txn.Steps {
		h, ok := e.lookupHandler(step.Mechanism)
		if !ok {
			return fmt.Errorf("preflight: step %d mechanism %q is not registered", step.Index, step.Mechanism)
		}
		if txn.Transactional && !h.Capturable() {
			return fmt.Errorf("preflight: transactional:true rule contains non-capturable step %d (%s); fix the rule's transactional declaration",
				step.Index, step.Mechanism)
		}
	}
	return nil
}

// shouldArmDeadman reports whether the transaction's mechanisms touch
// the SSH control channel and therefore require the deadman-timer
// out-of-band rollback path.
//
// The current heuristic is the mechanism allowlist below. As more
// mechanisms land, this evolves into a per-handler ControlChannelRisk
// query (TODO: tracked in BACKLOG).
func shouldArmDeadman(txn *api.Transaction, _ *handler.Registry) bool {
	for _, step := range txn.Steps {
		if controlChannelMechanisms[step.Mechanism] {
			return true
		}
	}
	return false
}

// controlChannelMechanisms is the static set of mechanisms whose
// changes can disable the SSH control channel. Conservative by design:
// false negatives risk atomicity violations, false positives only cost
// extra deadman scheduling.
var controlChannelMechanisms = map[string]bool{
	"config_set":            false, // generic — only some paths matter; per-rule tagging needed
	"config_set_dropin":     false, // same
	"service_enabled":       true,  // sshd, NetworkManager, firewalld
	"service_disabled":      true,
	"service_masked":        true,
	"pam_module_configure":  true,
	"audit_rule_set":        false,
	"sysctl_set":            false, // most sysctls are safe; net.* could matter
	"file_permissions":      false,
	"file_content":          false,
	"file_absent":           false,
	"package_present":       false,
	"package_absent":        true, // removing openssh-server bricks the channel
	"kernel_module_disable": false,
	"selinux_boolean_set":   false,
	"mount_option_set":      false,
	"cron_job":              false,
	"command_exec":          true, // arbitrary; assume worst case
	"manual":                false,
	"grub_parameter_set":    false,
	"grub_parameter_remove": false,
}
