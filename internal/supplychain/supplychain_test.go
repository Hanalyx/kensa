// Package supplychain holds the enforcement tests for the
// system-supply-chain spec: the go.mod direct-dependency set, the
// depguard allowlist, and the CI gates are asserted against the
// committed repo files so drift between the spec and reality fails the
// build. There is no production code here — the spec's guarantees are
// facts about the repository, verified from disk.
package supplychain

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// repoRoot walks up from this test file to the module root (the
// directory holding go.mod), so the assertions run regardless of cwd.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from test file")
		}
		dir = parent
	}
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// depguardAllowlist parses the module paths from the depguard main
// allow list in .golangci.yml, excluding the $gostd token and the
// Hanalyx module (which are structural, not third-party deps). The
// depguard config is the machine-checked SSOT for the allowlist.
func depguardAllowlist(t *testing.T) []string {
	t.Helper()
	cfg := readRepoFile(t, ".golangci.yml")
	// The allow list sits under `depguard:` → `rules:` → `main:` →
	// `allow:`; capture that block up to the next same-or-lower-indent
	// key, then pull the `- <path>` entries.
	block := regexp.MustCompile(`(?s)allow:\s*\n(.*?)\n\s{0,10}[a-z]`)
	m := block.FindStringSubmatch(cfg)
	if m == nil {
		t.Fatal("could not locate the depguard allow list in .golangci.yml")
	}
	entry := regexp.MustCompile(`(?m)^\s*-\s+(\S+)\s*$`)
	var out []string
	for _, e := range entry.FindAllStringSubmatch(m[1], -1) {
		p := e[1]
		if p == "$gostd" || p == "github.com/Hanalyx/kensa" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		t.Fatal("no third-party entries parsed from the depguard allow list")
	}
	sort.Strings(out)
	return out
}

// goModDirectDeps parses the direct (non-`// indirect`) requires from
// go.mod.
func goModDirectDeps(t *testing.T) []string {
	t.Helper()
	mod := readRepoFile(t, "go.mod")
	var out []string
	inBlock := false
	for _, line := range strings.Split(mod, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "require ("):
			inBlock = true
			continue
		case inBlock && trimmed == ")":
			inBlock = false
			continue
		}
		if !inBlock || trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "// indirect") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			out = append(out, fields[0])
		}
	}
	if len(out) == 0 {
		t.Fatal("no direct deps parsed from go.mod (expected a require block)")
	}
	sort.Strings(out)
	return out
}

// TestSupplyChain_AllowlistMatchesGoMod verifies go.mod's direct
// dependencies equal the depguard allow list (the machine-checked
// allowlist SSOT). A new direct dep must be allowlisted; a removed dep
// must be de-listed.
//
// @spec system-supply-chain
// @ac AC-01
func TestSupplyChain_AllowlistMatchesGoMod(t *testing.T) {
	t.Log("// @spec system-supply-chain")
	t.Log("// @ac AC-01")

	allow := depguardAllowlist(t)
	direct := goModDirectDeps(t)

	if strings.Join(allow, "\n") != strings.Join(direct, "\n") {
		t.Errorf("depguard allow list and go.mod direct deps differ.\ndepguard:\n  %s\ngo.mod direct:\n  %s\nA new direct dep must be added to the depguard allow list in .golangci.yml (with a rationale in specs/system/supply-chain.spec.yaml).",
			strings.Join(allow, "\n  "), strings.Join(direct, "\n  "))
	}
}

// TestSupplyChain_DepguardEnabled verifies depguard is enabled with the
// structural entries ($gostd and the Hanalyx module) present.
//
// @spec system-supply-chain
// @ac AC-02
func TestSupplyChain_DepguardEnabled(t *testing.T) {
	t.Log("// @spec system-supply-chain")
	t.Log("// @ac AC-02")

	cfg := readRepoFile(t, ".golangci.yml")
	if !strings.Contains(cfg, "depguard") {
		t.Fatal(".golangci.yml does not enable depguard")
	}
	for _, required := range []string{"$gostd", "github.com/Hanalyx/kensa"} {
		if !strings.Contains(cfg, required) {
			t.Errorf("depguard allow list missing structural entry %q", required)
		}
	}
}

// TestSupplyChain_CIGates verifies the read-only module mode, the
// govulncheck gate, and the go-mod-tidy drift gate are present in the CI
// workflow.
//
// @spec system-supply-chain
// @ac AC-03
// @ac AC-04
// @ac AC-05
func TestSupplyChain_CIGates(t *testing.T) {
	t.Log("// @spec system-supply-chain")

	ci := readRepoFile(t, ".github/workflows/ci.yml")

	t.Run("system-supply-chain/AC-03", func(t *testing.T) {
		if !regexp.MustCompile(`GOFLAGS:\s*'?-mod=readonly`).MatchString(ci) {
			t.Error("CI does not export GOFLAGS=-mod=readonly")
		}
	})
	t.Run("system-supply-chain/AC-04", func(t *testing.T) {
		if !strings.Contains(ci, "govulncheck") {
			t.Error("CI has no govulncheck gate")
		}
	})
	t.Run("system-supply-chain/AC-05", func(t *testing.T) {
		if !strings.Contains(ci, "go mod tidy") {
			t.Error("CI has no go-mod-tidy drift gate")
		}
	})
}

// TestSupplyChain_SBOMConfigured verifies the goreleaser config declares
// an sboms block producing a CycloneDX document.
//
// @spec system-supply-chain
// @ac AC-06
func TestSupplyChain_SBOMConfigured(t *testing.T) {
	t.Log("// @spec system-supply-chain")
	t.Log("// @ac AC-06")

	cfg := readRepoFile(t, ".goreleaser.yaml")
	if !regexp.MustCompile(`(?m)^sboms:`).MatchString(cfg) {
		t.Fatal(".goreleaser.yaml has no sboms block")
	}
	if !strings.Contains(cfg, "cyclonedx-json") {
		t.Error("sboms block does not produce a CycloneDX document")
	}
	if !strings.Contains(cfg, "sbom.cdx.json") {
		t.Error("sboms block does not name a kensa_<v>_sbom.cdx.json document")
	}
}
