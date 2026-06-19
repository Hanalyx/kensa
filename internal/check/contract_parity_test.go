package check

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// dispatchMethodsFromSource parses the method strings from the `switch chk.Method`
// dispatch in check.go — the ground truth for which methods the engine handles.
// Reading source (not a hardcoded list) makes this a real anti-drift gate: add a
// `case "x":` and the contract must gain "x", remove one and the contract must
// drop it.
func dispatchMethodsFromSource(t *testing.T) map[string]bool {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "check.go"))
	if err != nil {
		t.Fatalf("read check.go: %v", err)
	}
	// Restrict to the dispatch function body so sub-switches (e.g. selinux
	// "enforcing") don't leak in.
	body := string(src)
	if i := strings.Index(body, "func dispatch("); i >= 0 {
		body = body[i:]
		if j := strings.Index(body, "\nfunc "); j > 0 {
			// skip the func line itself then find the next top-level func
			if k := strings.Index(body[1:], "\nfunc "); k > 0 {
				body = body[:k+1]
			}
		}
	}
	re := regexp.MustCompile(`case\s+((?:"[a-z_]+"\s*,\s*)*"[a-z_]+")\s*:`)
	out := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		for _, q := range strings.Split(m[1], ",") {
			out[strings.Trim(strings.TrimSpace(q), `"`)] = true
		}
	}
	return out
}

// TestSchemaContractDispatchParity is the schema/engine anti-drift gate: the set
// of methods the dispatch handles MUST equal the set of methods in
// CheckContracts — in BOTH directions. PR-1 covered dispatch -> contract; this
// adds contract -> dispatch (no contract entry for a non-existent method) and
// derives the dispatch set from source so neither side can drift silently. The
// canonical schema §3.5.3 table is regenerated from CheckContracts, so this
// keeps the doc, the contract, and the engine in lockstep.
//
// @spec schema-parity
// @ac AC-01
func TestSchemaContractDispatchParity(t *testing.T) {
	t.Run("schema-parity/AC-01", func(t *testing.T) {})
	dispatch := dispatchMethodsFromSource(t)
	if len(dispatch) == 0 {
		t.Fatal("parsed zero dispatch methods — parser is broken")
	}

	var missingContract, extraContract []string
	for m := range dispatch {
		if !KnownCheckMethod(m) {
			missingContract = append(missingContract, m)
		}
	}
	for m := range CheckContracts {
		// file_permission is a documented alias sharing file_permissions'
		// contract; the dispatch lists both in one case.
		if !dispatch[m] {
			extraContract = append(extraContract, m)
		}
	}
	sort.Strings(missingContract)
	sort.Strings(extraContract)
	if len(missingContract) > 0 {
		t.Errorf("dispatch methods with no CheckContracts entry (add to contract): %v", missingContract)
	}
	if len(extraContract) > 0 {
		t.Errorf("CheckContracts entries with no dispatch case (stale contract entry): %v", extraContract)
	}
}
