package rule

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

// A capability probed by internal/detect but absent from KnownCapabilities is
// unusable: any rule gating on it fails validation with "not in the known
// capability set". The two lists live in different packages and nothing tied
// them together, so directory_joined was probed and unknown until this test.
//
// @spec catalog-coverage-crosswalk
// @ac AC-12
func TestEveryProbedCapabilityIsKnown(t *testing.T) {
	src, err := os.ReadFile("../detect/detect.go")
	if err != nil {
		t.Fatalf("read detect.go: %v", err)
	}
	// probe entries are `{\n\t\t"name",\n\t\t`cmd`,\n\t},` possibly with comments
	// between the brace and the name, so match the quoted name on its own line.
	re := regexp.MustCompile(`(?m)^\t\t"([a-z0-9_]+)",$`)
	var missing []string
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		if _, ok := KnownCapabilities[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(seen) == 0 {
		t.Fatal("parsed no probes from detect.go; the extraction broke, not the corpus")
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("capability %q is probed by internal/detect but missing from "+
			"KnownCapabilities, so no rule can gate on it", name)
	}
	t.Logf("%d probed capabilities, all registered", len(seen))
}
