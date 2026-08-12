package kensa

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
	panic("pkg-corpus-identity: not implemented")
}
