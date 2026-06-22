package auditruleset

import (
	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
)

// CapturedFootprint opts audit_rule_set into the agent-mode pre-commit gate.
// On the netlink path the apply touches exactly one filesystem resource — the
// /etc/audit/rules.d drop-in it captured (pre.Data["path"]); the rule
// load/unload happens over AUDIT netlink, which is not a filesystem mutation
// and so produces no observed footprint entry. The observed footprint must
// therefore be a subset of this single-file declaration.
func (h *Handler) CapturedFootprint(pre *api.PreState) (*footprint.Footprint, error) {
	return footprint.SingleFile(pre, "path")
}
