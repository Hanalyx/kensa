package filecontent

import (
	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
)

// CapturedFootprint opts file_content into the agent-mode pre-commit gate:
// the handler touches exactly the one file it captured (pre.Data["path"]),
// with no parent-directory creation, so its observed footprint must be a
// subset of this single-file declaration.
func (h *Handler) CapturedFootprint(pre *api.PreState) (*footprint.Footprint, error) {
	return footprint.SingleFile(pre, "path")
}
