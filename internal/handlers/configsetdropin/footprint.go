package configsetdropin

import (
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
)

// CapturedFootprint opts config_set_dropin into the agent-mode pre-commit
// gate. It declares the drop-in file (pre.Data["path"]) plus every ancestor
// directory Apply creates (pre.Data["created_dirs"], detected by Capture,
// routed through the transport's MkdirAll so the recorder observes them, and
// removed by Rollback). The observed footprint — the file write plus each
// created directory level — must be a subset of this declaration.
func (h *Handler) CapturedFootprint(pre *api.PreState) (*footprint.Footprint, error) {
	f, err := footprint.SingleFile(pre, "path")
	if err != nil {
		return nil, err
	}
	raw, _ := pre.Data["created_dirs"].(string)
	for _, d := range strings.Split(strings.TrimSpace(raw), "\n") {
		if d = strings.TrimSpace(d); d != "" {
			f.Add(footprint.Entry{
				Path:     d,
				Op:       footprint.OpCreate,
				PreImage: footprint.PreImage{Absent: true, IsDir: true},
			})
		}
	}
	return f, nil
}
