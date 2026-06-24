package catalog

import (
	"encoding/json"
	"fmt"
	"os"
)

// verification is a recorded functional-verification fact: a rule's check (and
// optionally remediate/rollback) proven to work on a live OS, read from the slim
// catalog/sources/verifications.json. It is independent of framework benchmarks —
// "Kensa knows this works here" is true whether or not CIS/STIG has published.
type verification struct {
	RuleID     string `json:"rule_id"`
	OS         string `json:"os"`
	Scope      string `json:"scope"` // check | remediate | rollback | full
	Host       string `json:"host"`
	VerifiedAt string `json:"verified_at"`
	Notes      string `json:"notes"`
}

func parseVerifications(path string) ([]verification, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read verifications: %w", err)
	}
	var doc struct {
		Verifications []verification `json:"verifications"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse verifications: %w", err)
	}
	return doc.Verifications, nil
}
