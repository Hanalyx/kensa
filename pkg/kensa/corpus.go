package kensa

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	rulespath "github.com/Hanalyx/kensa/internal/rules"
)

// Corpus identity, so a consumer can record what a verdict was measured
// against. Spec: pkg-corpus-identity.
//
// A scan result carries the host context through Capabilities. It does not
// carry the other half: which rule corpus decided the verdicts. The corpus
// ships as its own package and can be updated without the engine, so the
// linked module version does not describe it.

// Source values for [Corpus.Source]. A consumer must be able to tell a
// declared release from a computed fingerprint, so the two are never reported
// through the same field alone (spec pkg-corpus-identity C-04).
const (
	// SourceDeclared means the corpus carried a version marker and Version
	// holds it.
	SourceDeclared = "declared"
	// SourceComputed means the corpus carried no marker. Version is empty and
	// only Digest identifies it. A source checkout is the ordinary case.
	SourceComputed = "computed"
	// SourceNone means there is no corpus directory to describe, which happens
	// when a caller passes rule paths instead of a directory. Version and
	// Digest are both empty, because an empty digest here would claim the
	// corpus is empty rather than absent.
	SourceNone = "none"
)

// Corpus identifies the rule corpus at a directory.
//
// Both fields are reported because they answer different questions. Version
// answers "which release", which is what an operator or an assessor needs.
// Digest answers "is this the corpus that shipped", which a version cannot,
// because it detects local edits and covers a checkout carrying no version.
type Corpus struct {
	// Version is the declared corpus version, empty when the corpus carries
	// no marker.
	Version string
	// Digest is a sha256 over the rule files, always set when a corpus
	// directory exists. It covers each rule file's relative path and content,
	// because content alone does not change when a rule is renamed, and a rule
	// id must match its filename stem (spec C-02).
	Digest string
	// Source states which of the two above identifies this corpus. One of
	// SourceDeclared, SourceComputed or SourceNone.
	Source string
}

// DescribeCorpus reports the identity of the rule corpus that [LoadRules]
// would load for the same arguments.
//
// It resolves dir and paths exactly as LoadRules does, so it cannot describe a
// directory other than the one loaded (spec C-01). Passing rule paths with no
// directory yields SourceNone, since there is no corpus to describe.
//
// A corpus with no version marker is not an error. It returns an empty Version
// with SourceComputed, and never invents a version (spec C-05).
func DescribeCorpus(dir string, paths []string) (Corpus, error) {
	// C-01: the same resolution LoadRules performs, so the directory described
	// is the directory that would be loaded. Resolving separately here is the
	// bug this guards against: it would report a version for one corpus while
	// the caller scanned another.
	resolved, err := rulespath.Resolve(dir, paths, os.Stat)
	if err != nil {
		return Corpus{}, err
	}
	// Resolve returns "" when the caller passed rule paths and no directory.
	// There is no corpus to describe. An empty digest here would read as "the
	// corpus is empty" rather than "there is no corpus".
	if resolved == "" {
		return Corpus{Source: SourceNone}, nil
	}

	digest, err := corpusDigest(resolved)
	if err != nil {
		return Corpus{}, err
	}

	version, err := corpusMarker(resolved)
	if err != nil {
		return Corpus{}, err
	}
	if version == "" {
		// C-05: no marker is a normal state, not a fault. A source checkout
		// reaches here, and inventing a version would be worse than admitting
		// there is none.
		return Corpus{Digest: digest, Source: SourceComputed}, nil
	}
	return Corpus{Version: version, Digest: digest, Source: SourceDeclared}, nil
}

// corpusMarkerFile is the version marker inside a corpus directory. It carries
// no .yml extension on purpose (C-07): consumers count *.yml under the corpus
// to validate a build and walk the same tree for variables, so a .yml marker
// would be counted as a rule. walkRuleFiles matches on the extension, so this
// name is also excluded from the digest by construction (C-03).
const corpusMarkerFile = ".corpus-version"

// corpusMarker reads the declared version from a corpus directory. It returns
// "" when the marker is absent or blank, and an error only when the marker
// exists and cannot be read — that case must not be reported as "no marker",
// because a permissions failure would then masquerade as a source checkout.
func corpusMarker(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, corpusMarkerFile))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read corpus version marker in %s: %w", dir, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// corpusDigest hashes the rule files under dir.
//
// It covers each file's path RELATIVE to dir as well as its content (C-02).
// Content alone is not enough: measured over the 779-rule corpus, renaming one
// file left a content-only digest byte for byte identical, and a rule id must
// match its filename stem, so a rename changes rule identity.
//
// Relative rather than absolute, and slash-separated, so the same corpus
// digests the same whether it sits in a source checkout or at the packaged
// path, and on any host.
//
// Only *.yml is hashed, via the same walk LoadRules uses, so the version
// marker and anything else in the directory leave the digest alone (C-03).
func corpusDigest(dir string) (string, error) {
	files, err := walkRuleFiles(dir)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, p := range files {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return "", fmt.Errorf("relative path for %s: %w", p, err)
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", p, err)
		}
		// path, NUL, then the content's fixed-width digest. A path cannot
		// contain NUL and the digest is always 32 bytes, so no two different
		// corpora can produce the same byte stream by rearranging where one
		// field ends and the next begins.
		sum := sha256.Sum256(content)
		h.Write([]byte(filepath.ToSlash(rel)))
		h.Write([]byte{0})
		h.Write(sum[:])
	}
	// Self-describing, so a stored value states which algorithm produced it
	// and a future change of algorithm cannot be mistaken for a corpus change.
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
