package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	// `t.Run("spec-id/AC-NN", ...)` — Convention A.
	acSubtestRe = regexp.MustCompile(`t\.Run\("([a-z0-9][a-z0-9-]*)/(AC-\d+)"`)
	// `// @spec spec-id` … `// @ac AC-NN` — Convention B, in comments or t.Log.
	acAnnotationRe = regexp.MustCompile(`@ac\s+(AC-\d+)`)
	specAnnotRe    = regexp.MustCompile(`@spec\s+([a-z0-9][a-z0-9-]*)`)
	// `- id: AC-NN` inside a spec's acceptance_criteria.
	specACIDRe = regexp.MustCompile(`(?m)^\s+- id: (AC-\d+)\s*$`)
	// `#   - AC-NN (...)` inside a "Deferred ACs" comment block. Specs
	// deliberately RESERVE the IDs of deferred criteria so that
	// re-introduction preserves the historical numbering, and tests for the
	// deferred behavior may still carry the annotation. A reserved ID is
	// known, so naming it is not the defect this gate hunts.
	deferredACRe = regexp.MustCompile(`(?m)^\s*#\s*- (AC-\d+)\b`)
	specIDRe     = regexp.MustCompile(`(?m)^\s*id:\s*([a-z0-9][a-z0-9-]*)\s*$`)
)

// TestSpecACReferencesResolve is the inverse of [TestSpecTestReferencesResolve]:
// it checks that every acceptance criterion a TEST claims actually exists in
// the spec it names.
//
// Specter does not. An annotation naming an AC the spec does not define is
// accepted in silence — the test simply counts toward nothing — so the strict
// tier-coverage gate stays green while the property the author believed was
// locked is locked by nobody. Deleting the tests would not fail the build
// either, because the AC they cite has no existence to lose coverage of.
//
// This has happened twice in one change. Tests written against one branch's
// numbering were carried onto a branch whose spec numbered differently, and
// ten `@ac AC-14` annotations pointed at an AC that did not exist while
// `specter check --strict` reported 144/144 and the gate ran inert. The
// failure is silent in exactly the direction that matters: it looks like
// coverage.
//
// IDs reserved in a spec's "Deferred ACs" block count as known. Specs keep
// those numbers so re-introduction preserves the historical numbering, and a
// test for the deferred behavior may legitimately still carry the annotation;
// that is a documented convention, not the invented reference this hunts.
// knownStaleSpecACRefs is the ratcheting debt ledger for annotations that name
// a spec or acceptance criterion which does not exist, mirroring
// knownStaleSpecTestRefs for the inverse direction.
//
// An entry is either "spec-id" (the whole spec is unresolved) or
// "spec-id/AC-NN". To clear one: point the annotation at the spec that actually
// covers the behavior, or add the criterion. Goal: empty.
//
// Provenance: found by this gate on its first run, 2026-08-02. Pre-existing and
// unrelated to the change that added the gate, so it is ledgered rather than
// fixed blind — retargeting it means deciding which spec owns the behavior,
// which belongs with someone who owns that subsystem.
var knownStaleSpecACRefs = map[string]bool{
	// internal/check/config_value_dropin_test.go annotates @spec check-model.
	// No spec declares that ID; the nearest candidates are check-param-contract
	// and check-observation-evidence, and choosing between them is a judgement
	// about which owns drop-in config_value semantics.
	"check-model": true,
}

func TestSpecACReferencesResolve(t *testing.T) {
	root := validateRepoRoot()

	// 1. Every AC each spec actually defines, keyed by spec ID.
	specACs := map[string]map[string]bool{}
	_ = filepath.WalkDir(filepath.Join(root, "specs"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".spec.yaml") {
			return nil //nolint:nilerr // unreadable entries are not this gate's business
		}
		b, rerr := os.ReadFile(path) //nolint:gosec // walking a fixed repo subtree
		if rerr != nil {
			return nil
		}
		m := specIDRe.FindSubmatch(b)
		if m == nil {
			return nil
		}
		acs := map[string]bool{}
		for _, hit := range specACIDRe.FindAllSubmatch(b, -1) {
			acs[string(hit[1])] = true
		}
		for _, hit := range deferredACRe.FindAllSubmatch(b, -1) {
			acs[string(hit[1])] = true
		}
		specACs[string(m[1])] = acs
		return nil
	})
	if len(specACs) == 0 {
		t.Fatal("found no specs to check; the walk or the repo root is wrong")
	}

	// 2. Every (spec, AC) pair a test claims.
	type claim struct{ spec, ac, file string }
	var claims []claim
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil //nolint:nilerr // same
		}
		// Exclusions are matched against the path RELATIVE to the repo root,
		// never the absolute one. An absolute-substring test excludes the whole
		// tree whenever the CHECKOUT itself lives under a matching directory --
		// a worktree under .../scratchpad/ made this walk find nothing and fail
		// with "found no @spec/@ac claims". It failed loudly rather than passing
		// vacuously, which is the safe direction, but it is still a gate that
		// cannot run where the reviewer put the checkout.
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "vendor/") || strings.Contains(rel, "/vendor/") ||
			strings.HasPrefix(rel, "scratchpad/") || strings.Contains(rel, "/scratchpad/") {
			return nil
		}
		b, rerr := os.ReadFile(path) //nolint:gosec // walking a fixed repo subtree
		if rerr != nil {
			return nil
		}
		src := string(b)

		// Convention A carries both IDs in one string.
		for _, hit := range acSubtestRe.FindAllStringSubmatch(src, -1) {
			claims = append(claims, claim{spec: hit[1], ac: hit[2], file: rel})
		}
		// Convention B pairs a file-local @spec with each @ac. Only meaningful
		// when the file names exactly one spec; otherwise the pairing is
		// ambiguous and Convention A should have been used.
		specHits := specAnnotRe.FindAllStringSubmatch(src, -1)
		named := map[string]bool{}
		for _, h := range specHits {
			named[h[1]] = true
		}
		if len(named) == 1 {
			var only string
			for k := range named {
				only = k
			}
			for _, hit := range acAnnotationRe.FindAllStringSubmatch(src, -1) {
				claims = append(claims, claim{spec: only, ac: hit[1], file: rel})
			}
		}
		return nil
	})
	if len(claims) == 0 {
		t.Fatal("found no @spec/@ac claims; the annotation conventions or the walk changed")
	}

	var bad []string
	seen := map[string]bool{}
	skipped := 0
	for _, c := range claims {
		if knownStaleSpecACRefs[c.spec+"/"+c.ac] || knownStaleSpecACRefs[c.spec] {
			skipped++
			continue
		}
		acs, ok := specACs[c.spec]
		if !ok {
			// An unknown SPEC id is a different defect and is not this gate's
			// job; report it rather than silently skipping.
			key := c.file + " -> spec " + c.spec
			if !seen[key] {
				seen[key] = true
				bad = append(bad, c.file+": names spec "+c.spec+", which does not exist")
			}
			continue
		}
		if !acs[c.ac] {
			key := c.spec + "/" + c.ac + " " + c.file
			if !seen[key] {
				seen[key] = true
				bad = append(bad, c.file+": claims "+c.spec+"/"+c.ac+", which that spec does not define")
			}
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s", b)
	}
	if skipped > 0 {
		t.Logf("tolerated %d claim(s) via knownStaleSpecACRefs; goal is an empty ledger", skipped)
	}
	if len(bad) > 0 {
		t.Log("An @ac naming an AC the spec does not define counts toward nothing, " +
			"and specter accepts it silently — the tier-coverage gate stays green " +
			"while the property is locked by no one. Fix the annotation or add the AC.")
	}
}
