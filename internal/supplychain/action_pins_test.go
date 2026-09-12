package supplychain

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Third-party actions run code Kensa does not own, and a tag is mutable: the
// owner can move it to a different commit and the next run executes something
// else. In the release job those actions share a job with the GPG and cosign
// secrets. A full commit SHA is the only immutable way to name an action, so
// these tests hold every reference to one.
//
// The comparison is against the mapping approved in
// specs/system/immutable-action-pins.spec.yaml, not merely against itself.
// Checking references only for internal consistency would accept a whole
// workflow re-pinned to some other commit. It is deliberately offline:
// verifying a SHA against its upstream tag is a two-source review step done
// when a pin changes, and making CI reach GitHub to lint itself would fail the
// build whenever GitHub is unreachable.

type actionPin struct {
	sha   string
	tag   string
	count int
}

// approvedPins mirrors the spec. Changing a pin means changing both, and the
// upstream tag must be re-verified from two sources at that time.
var approvedPins = map[string]actionPin{
	"actions/checkout":              {"3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1", 17}, // pragma: allowlist secret
	"actions/setup-go":              {"924ae3a1cded613372ab5595356fb5720e22ba16", "v6.5.0", 14}, // pragma: allowlist secret
	"actions/setup-python":          {"ece7cb06caefa5fff74198d8649806c4678c61a1", "v6.3.0", 1},  // pragma: allowlist secret
	"actions/upload-artifact":       {"043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "v7.0.1", 2},  // pragma: allowlist secret
	"golangci/golangci-lint-action": {"ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a", "v9.3.0", 1},  // pragma: allowlist secret
	"sigstore/cosign-installer":     {"398d4b0eeef1380460a10c8013a76f728fb906ac", "v3.9.1", 1},  // pragma: allowlist secret
}

const totalExternalRefs = 36

var pinnedWorkflows = []string{
	".github/workflows/ci.yml",
	".github/workflows/release.yml",
}

// usesLine captures the reference and any trailing comment on the same line.
var usesLine = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)\s*(#.*)?$`)

type reference struct {
	file    string
	raw     string
	comment string
}

func collectReferences(t *testing.T) []reference {
	t.Helper()
	var refs []reference
	for _, wf := range pinnedWorkflows {
		body := readRepoFile(t, wf)
		for _, m := range usesLine.FindAllStringSubmatch(body, -1) {
			refs = append(refs, reference{file: wf, raw: m[1], comment: strings.TrimSpace(m[2])})
		}
	}
	return refs
}

// TestActionPins_EveryExternalReferenceIsPinned is the whole contract: the
// exact SHA, the exact tag comment, and the exact per-action counts.
//
// @spec system-immutable-action-pins
// @ac AC-01
func TestActionPins_EveryExternalReferenceIsPinned(t *testing.T) {
	t.Log("// @spec system-immutable-action-pins")
	t.Log("// @ac AC-01")

	refs := collectReferences(t)
	seen := map[string]int{}
	external := 0

	for _, r := range refs {
		// Local actions are repository-owned and exempt.
		if strings.HasPrefix(r.raw, "./") {
			continue
		}
		external++

		if strings.HasPrefix(r.raw, "docker://") {
			t.Errorf("%s: docker reference %q is not an allowed action form", r.file, r.raw)
			continue
		}

		at := strings.LastIndex(r.raw, "@")
		if at < 0 {
			t.Errorf("%s: reference %q has no version at all", r.file, r.raw)
			continue
		}
		action, rev := r.raw[:at], r.raw[at+1:]

		want, ok := approvedPins[action]
		if !ok {
			t.Errorf("%s: %q is not in the approved pin set; add it to the spec and to approvedPins deliberately", r.file, action)
			continue
		}
		seen[action]++

		// A tag, a branch or a short SHA are all mutable.
		if len(rev) != 40 {
			t.Errorf("%s: %s is pinned to %q (%d chars); a full 40-character SHA is required", r.file, action, rev, len(rev))
			continue
		}
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(rev) {
			t.Errorf("%s: %s revision %q is not lowercase hexadecimal", r.file, action, rev)
			continue
		}
		if rev != want.sha {
			t.Errorf("%s: %s pinned to %s, approved SHA is %s", r.file, action, rev, want.sha)
		}
		// The comment is what keeps the pin readable and is the form
		// Dependabot rewrites when it bumps a pin.
		wantComment := "# " + want.tag
		if r.comment != wantComment {
			t.Errorf("%s: %s comment is %q, want %q", r.file, action, r.comment, wantComment)
		}
	}

	if external != totalExternalRefs {
		t.Errorf("found %d external references, spec approves %d", external, totalExternalRefs)
	}
	for action, want := range approvedPins {
		if seen[action] != want.count {
			t.Errorf("%s appears %d times, spec approves %d", action, seen[action], want.count)
		}
	}
	for action := range seen {
		if _, ok := approvedPins[action]; !ok {
			t.Errorf("unapproved action %q present", action)
		}
	}
}

// TestActionPins_NoMutableReferenceForms catches the shapes that would
// reintroduce mutability even if the counts happened to line up.
//
// @spec system-immutable-action-pins
// @ac AC-01
func TestActionPins_NoMutableReferenceForms(t *testing.T) {
	t.Log("// @spec system-immutable-action-pins")
	t.Log("// @ac AC-01")

	tagLike := regexp.MustCompile(`@(v[0-9][^\s#]*|main|master|latest|HEAD)$`)
	for _, r := range collectReferences(t) {
		if strings.HasPrefix(r.raw, "./") {
			continue
		}
		if tagLike.MatchString(r.raw) {
			t.Errorf("%s: %q is a mutable reference (tag or branch)", r.file, r.raw)
		}
	}
}

// TestActionPins_SpecMatchesTest keeps the committed mapping and the approved
// spec from drifting apart: a pin bumped in one place only must fail.
//
// @spec system-immutable-action-pins
// @ac AC-01
func TestActionPins_SpecMatchesTest(t *testing.T) {
	t.Log("// @spec system-immutable-action-pins")
	t.Log("// @ac AC-01")

	spec := readRepoFile(t, "specs/system/immutable-action-pins.spec.yaml")
	for action, want := range approvedPins {
		for _, fragment := range []string{action + ":", "sha: " + want.sha, "tag: " + want.tag} {
			if !strings.Contains(spec, fragment) {
				t.Errorf("spec does not carry %q for %s", fragment, action)
			}
		}
	}
	if !strings.Contains(spec, fmt.Sprintf("total_external_references: %d", totalExternalRefs)) {
		t.Errorf("spec does not declare total_external_references: %d", totalExternalRefs)
	}
	for action, want := range approvedPins {
		if !strings.Contains(spec, fmt.Sprintf("count: %d", want.count)) {
			t.Errorf("spec does not declare count %d for %s", want.count, action)
		}
	}
}
