package configappend

import (
	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
)

// CapturedFootprint opts config_append into the agent-mode pre-commit gate:
// the kernel-IO apply rewrites exactly the one file it captured
// (pre.Data["path"]) — appending a line — with no parent-directory creation,
// so its observed footprint must be a subset of this single-file declaration.
func (h *Handler) CapturedFootprint(pre *api.PreState) (*footprint.Footprint, error) {
	return footprint.SingleFile(pre, "path")
}
