package catalog

import (
	"encoding/json"
	"fmt"
	"os"
)

// cisFacts is the non-copyrightable CIS facts export produced by cis_facts.py.
// It deliberately carries no recommendation title or prose: CIS benchmark text is
// copyrighted and is never stored in the catalog. Only the recommendation number,
// profile level, and automatable flag (all facts, not expression) are ingested.
type cisFacts struct {
	Framework       string   `json:"framework"`
	OS              string   `json:"os"`
	Version         string   `json:"version"`
	Recommendations []cisRec `json:"recommendations"`
}

type cisRec struct {
	Section     string `json:"section"`
	Level       string `json:"level"` // L1 | L2 | ""
	Automatable bool   `json:"automatable"`
}

func parseCISFacts(path string) (cisFacts, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cisFacts{}, fmt.Errorf("read cis facts: %w", err)
	}
	var f cisFacts
	if err := json.Unmarshal(data, &f); err != nil {
		return cisFacts{}, fmt.Errorf("parse cis facts: %w", err)
	}
	if f.OS == "" || f.Version == "" {
		return cisFacts{}, fmt.Errorf("cis facts missing os or version")
	}
	return f, nil
}
