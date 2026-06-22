package configset

import (
	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
)

// CapturedFootprint opts config_set into the agent-mode pre-commit gate: the
// handler modifies exactly the one config file it captured
// (pre.Data["path"]) in place, with no parent-directory creation, so its
// observed footprint must be a subset of this single-file declaration.
// config_set records the edited file under pre.Data["file"].
func (h *Handler) CapturedFootprint(pre *api.PreState) (*footprint.Footprint, error) {
	return footprint.SingleFile(pre, "file")
}
