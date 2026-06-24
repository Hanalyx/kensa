package catalog

import (
	"encoding/xml"
	"fmt"
	"os"
)

// stigBenchmark mirrors the parts of a DISA STIG XCCDF 1.1 document we ingest.
// encoding/xml matches on local element name and ignores the namespace, so the
// xccdf default namespace needs no prefix here.
type stigBenchmark struct {
	XMLName xml.Name    `xml:"Benchmark"`
	Title   string      `xml:"title"`
	Groups  []stigGroup `xml:"Group"`
}

// stigGroup is one requirement. DISA manual STIGs are flat (Benchmark -> Group ->
// Rule), but Group nesting is permitted by the schema, so sub-groups are flattened.
type stigGroup struct {
	ID     string      `xml:"id,attr"` // V-xxxxxx
	Rule   stigRule    `xml:"Rule"`
	Groups []stigGroup `xml:"Group"`
}

type stigRule struct {
	Severity string      `xml:"severity,attr"`
	Version  string      `xml:"version"` // STIG id, e.g. RHEL-09-611070
	Title    string      `xml:"title"`
	Idents   []stigIdent `xml:"ident"`
}

type stigIdent struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

// parsedControl is the framework-neutral row the ingest layer persists.
type parsedControl struct {
	ControlID   string // vuln id
	SecondaryID string // STIG id
	Severity    string // high | medium | low
	Title       string
	CCIs        []string
}

// parseSTIG reads a STIG XCCDF file and returns its title plus one parsedControl
// per requirement (flattening any nested Groups).
func parseSTIG(path string) (title string, controls []parsedControl, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read xccdf: %w", err)
	}
	var b stigBenchmark
	if err := xml.Unmarshal(data, &b); err != nil {
		return "", nil, fmt.Errorf("parse xccdf: %w", err)
	}
	var walk func(g stigGroup)
	walk = func(g stigGroup) {
		if g.ID != "" {
			var ccis []string
			for _, id := range g.Rule.Idents {
				if containsFold(id.System, "cci") && id.Value != "" {
					ccis = append(ccis, id.Value)
				}
			}
			controls = append(controls, parsedControl{
				ControlID:   g.ID,
				SecondaryID: g.Rule.Version,
				Severity:    g.Rule.Severity,
				Title:       g.Rule.Title,
				CCIs:        ccis,
			})
		}
		for _, sub := range g.Groups {
			walk(sub)
		}
	}
	for _, g := range b.Groups {
		walk(g)
	}
	return b.Title, controls, nil
}

// containsFold reports whether s contains sub, case-insensitively, without
// allocating via strings.ToLower on every call.
func containsFold(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
