// Package mappings converts the raw `references` block from a V1 canonical
// rule YAML file into a flat slice of [api.FrameworkRef] values.
//
// # V0 References Format
//
// The V0/V1 references block supports two shapes, as specified in
// docs/CANONICAL_RULE_SCHEMA_V1.md §3.3:
//
//  1. Versioned-object frameworks (CIS, STIG): the framework key maps to an
//     object whose keys are OS-version identifiers (e.g., "rhel9"), and each
//     value is an object with a primary control identifier:
//
//     - CIS: the `section` field is the control ID.
//     - STIG: the `vuln_id` field is the control ID.
//
//  2. Flat-list frameworks (nist_800_53, pci_dss_4, iso27001_2022, cmmc_l2,
//     hipaa, srg, …): the framework key maps to a list of control-ID strings.
//
// # Output
//
// [RefsFromReferences] normalises both shapes into a flat
// []api.FrameworkRef slice. Each element has a FrameworkID of the form
// "<framework>_<osversion>" for versioned frameworks, or just the top-level
// framework key for flat-list frameworks.
package mappings

import (
	"fmt"

	"github.com/Hanalyx/kensa-go/api"
)

// RefsFromReferences converts the raw references map decoded from a rule YAML
// file into a flat slice of [api.FrameworkRef] values.
//
// Unrecognized reference shapes are silently skipped; the caller receives
// whatever can be parsed. This is intentional: new frameworks added to rule
// YAML before the loader is updated should not break parsing.
func RefsFromReferences(refs map[string]interface{}) []api.FrameworkRef {
	if len(refs) == 0 {
		return nil
	}
	var out []api.FrameworkRef
	for framework, value := range refs {
		switch v := value.(type) {
		case map[string]interface{}:
			// Versioned-object framework: keys are OS-version identifiers.
			for osVersion, detail := range v {
				frameworkID := fmt.Sprintf("%s_%s", framework, osVersion)
				controlID := extractVersionedControlID(framework, detail)
				if controlID == "" {
					continue
				}
				out = append(out, api.FrameworkRef{
					FrameworkID: frameworkID,
					ControlID:   controlID,
				})
			}
		case []interface{}:
			// Flat-list framework: each element is a control-ID string.
			for _, item := range v {
				controlID, ok := item.(string)
				if !ok || controlID == "" {
					continue
				}
				out = append(out, api.FrameworkRef{
					FrameworkID: framework,
					ControlID:   controlID,
				})
			}
		}
	}
	return out
}

// extractVersionedControlID extracts the primary control identifier from a
// versioned-framework detail object. The extraction strategy is determined by
// the framework name:
//
//   - "cis": the "section" field.
//   - "stig": the "vuln_id" field.
//   - All others: the first string field encountered (best-effort).
func extractVersionedControlID(framework string, detail interface{}) string {
	obj, ok := detail.(map[string]interface{})
	if !ok {
		return ""
	}
	switch framework {
	case "cis":
		return stringField(obj, "section")
	case "stig":
		return stringField(obj, "vuln_id")
	default:
		// Best-effort: return the first string field found so that
		// unrecognized versioned frameworks still produce a ref.
		for _, v := range obj {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
}

// stringField returns the string value of key in obj, or "" when absent or
// not a string.
func stringField(obj map[string]interface{}, key string) string {
	v, ok := obj[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
