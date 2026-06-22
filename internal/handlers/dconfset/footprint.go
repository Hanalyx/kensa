package dconfset

import (
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
)

// CapturedFootprint opts dconf_set into the agent-mode pre-commit gate. It
// declares the superset of resources Apply may touch through the funnel: the
// snippet, the lock, the shared profile, and every ancestor directory Apply
// creates (db dir + locks dir). Over-declaring (e.g. the lock when the rule
// does not lock, or the profile when it already exists) is safe — the gate
// only fails on an OBSERVED resource missing from the captured set, so a
// captured superset always passes while still catching an unexpected touch.
func (h *Handler) CapturedFootprint(pre *api.PreState) (*footprint.Footprint, error) {
	if pre == nil || pre.Data == nil {
		return nil, errMissingSchema
	}
	f := footprint.New()
	for _, key := range []string{"file_path", "lock_path", "profile_path"} {
		if p, _ := pre.Data[key].(string); p != "" {
			f.Add(footprint.Entry{Path: p, Op: footprint.OpModify})
		}
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
