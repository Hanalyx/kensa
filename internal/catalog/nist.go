package catalog

import (
	"encoding/json"
	"fmt"
	"os"
)

// nistControl is one NIST SP 800-53 catalog control (base or enhancement), read
// from the slim derived facts file catalog/sources/nist/nist_800-53_r5_controls.json.
type nistControl struct {
	ID     string `json:"id"`     // OSCAL id, e.g. ac-3 or ac-3.4
	Family string `json:"family"` // family id, e.g. ac
	Title  string `json:"title"`
}

// parseNISTControls reads the slim 800-53 rev5 controls facts file. The heavy raw
// OSCAL catalog is reduced to id/family/title by catalog/sources/nist/derive_nist_facts.py;
// only the slim file is vendored.
func parseNISTControls(path string) ([]nistControl, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read nist controls: %w", err)
	}
	var out []nistControl
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse nist controls: %w", err)
	}
	return out, nil
}

// cciEdge is a CCI-to-800-53-control crosswalk edge, read from the slim derived
// facts file catalog/sources/nist/cci_800-53_r5_edges.json.
type cciEdge struct {
	CCI       string `json:"cci"`
	ControlID string `json:"control"` // normalized OSCAL id, e.g. ac-3 or ac-3.4
}

// parseCCIEdges reads the slim CCI-to-800-53-rev5 edges file. The raw DISA CCI XML
// is reduced to (cci, control) rev5 edges by derive_nist_facts.py; only the slim
// file is vendored.
func parseCCIEdges(path string) ([]cciEdge, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cci edges: %w", err)
	}
	var out []cciEdge
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse cci edges: %w", err)
	}
	return out, nil
}
