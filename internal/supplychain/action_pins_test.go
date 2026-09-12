package supplychain

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// discoverWorkflowFiles finds every workflow and every local composite
// action definition under .github, rather than naming files. A hard-coded
// list silently exempts anything added later: a new workflow carrying an
// unpinned action would never be looked at.
func discoverWorkflowFiles(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	var out []string
	for _, dir := range []string{
		filepath.Join(root, ".github", "workflows"),
		filepath.Join(root, ".github", "actions"),
	} {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil // .github/actions need not exist
				}
				return err
			}
			if info.IsDir() {
				return nil
			}
			if ext := filepath.Ext(path); ext == ".yml" || ext == ".yaml" {
				rel, rerr := filepath.Rel(root, path)
				if rerr != nil {
					return rerr
				}
				out = append(out, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("discovered no workflow files; the walk is broken")
	}
	return out
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
	for _, wf := range discoverWorkflowFiles(t) {
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

// TestActionPins_SpecMatchesTest deep-compares the committed mapping against
// the approved spec, entry by entry.
//
// Searching the spec text for each value separately is not enough: every value
// would still be "present" after two actions had their SHA, tag and count
// blocks swapped with each other, because nothing ties a value to the action
// it belongs to. The spec is therefore parsed and compared as a structure.
//
// @spec system-immutable-action-pins
// @ac AC-01
func TestActionPins_SpecMatchesTest(t *testing.T) {
	t.Log("// @spec system-immutable-action-pins")
	t.Log("// @ac AC-01")

	var doc struct {
		Spec struct {
			AcceptanceCriteria []struct {
				ID     string `yaml:"id"`
				Inputs struct {
					ApprovedPins map[string]struct {
						SHA   string `yaml:"sha"`
						Tag   string `yaml:"tag"`
						Count int    `yaml:"count"`
					} `yaml:"approved_pins"`
					TotalExternalReferences int `yaml:"total_external_references"`
				} `yaml:"inputs"`
			} `yaml:"acceptance_criteria"`
		} `yaml:"spec"`
	}
	raw := readRepoFile(t, "specs/system/immutable-action-pins.spec.yaml")
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("parsing the pin spec: %v", err)
	}

	var pins map[string]struct {
		SHA   string `yaml:"sha"`
		Tag   string `yaml:"tag"`
		Count int    `yaml:"count"`
	}
	total := 0
	for _, ac := range doc.Spec.AcceptanceCriteria {
		if ac.ID == "AC-01" {
			pins = ac.Inputs.ApprovedPins
			total = ac.Inputs.TotalExternalReferences
		}
	}
	if pins == nil {
		t.Fatal("spec AC-01 declares no approved_pins")
	}

	if len(pins) != len(approvedPins) {
		t.Errorf("spec approves %d actions, the test holds %d", len(pins), len(approvedPins))
	}
	// Every action in the test must match its OWN entry in the spec.
	for action, want := range approvedPins {
		got, ok := pins[action]
		if !ok {
			t.Errorf("spec has no entry for %s", action)
			continue
		}
		if got.SHA != want.sha {
			t.Errorf("%s: spec sha %s, test sha %s", action, got.SHA, want.sha)
		}
		if got.Tag != want.tag {
			t.Errorf("%s: spec tag %s, test tag %s", action, got.Tag, want.tag)
		}
		if got.Count != want.count {
			t.Errorf("%s: spec count %d, test count %d", action, got.Count, want.count)
		}
	}
	// And nothing extra may live in the spec.
	for action := range pins {
		if _, ok := approvedPins[action]; !ok {
			t.Errorf("spec approves %s, which the test does not hold", action)
		}
	}

	if total != totalExternalRefs {
		t.Errorf("spec total_external_references is %d, test holds %d", total, totalExternalRefs)
	}
	sum := 0
	for _, p := range pins {
		sum += p.Count
	}
	if sum != total {
		t.Errorf("spec per-action counts sum to %d but total_external_references is %d", sum, total)
	}
}
