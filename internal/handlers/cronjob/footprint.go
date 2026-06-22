package cronjob

import (
	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
)

// CapturedFootprint opts cron_job into the agent-mode pre-commit gate: the
// kernel-IO apply writes exactly the one /etc/cron.d/ file it captured
// (pre.Data["path"]) — /etc/cron.d/ already exists, so there is no directory
// creation — and its observed footprint must be a subset of this single-file
// declaration.
func (h *Handler) CapturedFootprint(pre *api.PreState) (*footprint.Footprint, error) {
	return footprint.SingleFile(pre, "path")
}
