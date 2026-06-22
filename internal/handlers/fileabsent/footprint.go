package fileabsent

import (
	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
)

// CapturedFootprint opts file_absent into the agent-mode pre-commit gate:
// the handler touches exactly the one file it captured (pre.Data["path"]) —
// the file it removes — so its observed footprint must be a subset of this
// single-file declaration.
func (h *Handler) CapturedFootprint(pre *api.PreState) (*footprint.Footprint, error) {
	return footprint.SingleFile(pre, "path")
}
