package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// knownStaleSpecTestRefs is the ratcheting debt ledger for spec prose that
// names a Go test which does not exist — a test renamed/restructured out from
// under a "Locked by TestX" reference, or one named but never written.
//
// The strict-coverage gate cannot catch this: it maps tests to acceptance
// criteria by @spec/@ac ANNOTATION ID, not by checking the spec's prose against
// the tree, so a "Locked by TestX" reference rots silently while coverage stays
// green. [TestSpecTestReferencesResolve] closes that hole.
//
// Each entry is an unresolved test identifier exactly as it appears in specs/.
// To clear one: re-point the spec to the real test name (a rename), or write
// the missing test (a genuine coverage gap), then delete its entry here. The
// ratchet below FAILS if a ledger entry is no longer unresolved, so the ledger
// can only shrink. Goal: empty.
//
// Provenance: spec-prose drift audit, 2026-06-15. Of the 12 affected specs, 11
// are at 100% AC coverage (their entries are pure renames); agent-bootstrap is
// at 83% and holds the one genuine missing-test gap.
var knownStaleSpecTestRefs = map[string]bool{
	// agent/handler-ports-umbrella (100% covered → renames)
	"TestAgentApply_CronJob":            true,
	"TestAgentApply_PAMModuleConfigure": true,
	"TestAgentApply_SysctlSet":          true,
	"TestAgentRoutesToHandler_":         true,
	// agent/handler-port-filepermissions (100% → renames; agent e2e is TestKensaAgent_*)
	"TestEngine_AgentCrashIsStranded":           true,
	"TestEngine_AgentMode_EndToEnd":             true,
	"TestEngine_AgentMode_IdenticalToDirectSSH": true,
	"TestRemoteHandler_Apply":                   true,
	// agent/cli-env-var (100% → rename; real test is TestDefaultWithEngineOptions_ExtraOptionsApplied)
	"TestDefaultWithEngineOptions_AgentRouting": true,
	// agent/stdio-subcommand (100% → renames)
	"TestRunEcho_HappyPath":           true,
	"TestRunEcho_PreCancelledContext": true,
	// agent/bootstrap (83% → one rename + the one genuine MISSING-TEST gap)
	"TestEnsureAgent_CacheMiss_PushesBinary": true,
	"TestEnsureAgent_PushFailure":            true,
	// cli/manpage (100% → renames; real tests are TestEscapeRoffLine / TestSubcommandList*)
	"TestEscapeRoff":                       true,
	"TestGenManpage_AllSubcommandsCovered": true,
	"TestGenManpage_Deterministic":         true,
	"TestGenManpage_FooterSectionsPresent": true,
	"TestGenManpage_HeaderSectionsPresent": true,
	// cli/oscal-regression (100% → renames; real tests are TestOSCALGolden_All / _StructuralPaths / _RegenerateRoundTrip)
	"TestOSCALGolden_Committed":      true,
	"TestOSCALGolden_MultiFramework": true,
	"TestOSCALGolden_RolledBack":     true,
	// remaining cli + deadman (100% → renames)
	"TestDeprecation_FormatFlag_ShortFormFires": true,
	"TestEventLoop_Close":                       true,
	"TestQuietFlag_NotInCoverage":               true,
	"TestRunAgent_StdioExitsRuntime":            true,
	"TestRunHistory_PruneNoForceNonTTY":         true,
}

var (
	// specTestRefRe matches a Go test identifier referenced in spec prose.
	specTestRefRe = regexp.MustCompile(`Test[A-Z][A-Za-z0-9_]*`)
	// funcTestRe matches a real test-function definition.
	funcTestRe = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
)

func validateRepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// TestSpecTestReferencesResolve fails when a spec names a Go test that does not
// exist in the tree, unless that reference is a tolerated entry in
// knownStaleSpecTestRefs. It also ratchets: a ledger entry that now resolves (or
// is no longer referenced) fails too, so stale debt cannot linger once fixed.
func TestSpecTestReferencesResolve(t *testing.T) {
	root := validateRepoRoot()

	// 1. Every real test-function name in the tree.
	realTests := map[string]bool{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			b, _ := os.ReadFile(path)
			for _, m := range funcTestRe.FindAllSubmatch(b, -1) {
				realTests[string(m[1])] = true
			}
		}
		return nil
	})

	// A spec token resolves if a test is named exactly that, or — when the
	// token is an explicit prefix family (trailing "_") — some test starts with
	// it. Exact names require exact tests; only "_"-suffixed tokens get prefix
	// matching, so "TestFoo" does not silently match an unrelated "TestFooBar".
	resolves := func(tok string) bool {
		if realTests[tok] {
			return true
		}
		if strings.HasSuffix(tok, "_") {
			for name := range realTests {
				if strings.HasPrefix(name, tok) {
					return true
				}
			}
		}
		return false
	}

	// 2. Scan every spec for test references and collect the unresolved ones.
	type loc struct {
		file string
		line int
	}
	unresolved := map[string][]loc{}
	specDir := filepath.Join(root, "specs")
	_ = filepath.WalkDir(specDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".spec.yaml") {
			return nil
		}
		b, _ := os.ReadFile(path)
		for i, line := range strings.Split(string(b), "\n") {
			for _, tok := range specTestRefRe.FindAllString(line, -1) {
				if !resolves(tok) {
					rel, _ := filepath.Rel(root, path)
					unresolved[tok] = append(unresolved[tok], loc{rel, i + 1})
				}
			}
		}
		return nil
	})

	// 3. NEW drift: an unresolved reference not yet in the ledger.
	var newDrift []string
	for tok, locs := range unresolved {
		if !knownStaleSpecTestRefs[tok] {
			newDrift = append(newDrift, fmt.Sprintf("%s\t(%s:%d)", tok, locs[0].file, locs[0].line))
		}
	}
	sort.Strings(newDrift)
	for _, d := range newDrift {
		t.Errorf("spec names a test that does not exist — write the test, fix the name, "+
			"or (if intentional) add it to knownStaleSpecTestRefs: %s", d)
	}

	// 4. Ratchet: a ledger entry that is no longer unresolved must be removed.
	for tok := range knownStaleSpecTestRefs {
		if _, stillStale := unresolved[tok]; !stillStale {
			t.Errorf("ratchet: %q is in knownStaleSpecTestRefs but now resolves or is no "+
				"longer referenced — remove it from the ledger", tok)
		}
	}
}
