// Package output is the home for the kensa CLI's --output FORMAT[:PATH]
// mechanism (deliverable C-011 in docs/roadmap/DELIVERABLES.md).
//
// The package is built up across CLI Phase 2:
//
//   - C-011 (this file): Spec type, Parse, ParseAll, format registry
//   - C-012: refactor existing serializers (json, jsonl, table) into
//     this package behind a common Writer interface
//   - C-013/C-015: csv, pdf serializers
//   - C-016/C-017: oscal, evidence serializers
//   - C-019: concurrent fan-out for multi-output runs
//
// Phase 2's design lifts the canonical -o FORMAT[:PATH] from Python
// kensa (see docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md §6) and
// extends it with kensa-go-specific formats (jsonl, oscal). Operators
// can request multiple simultaneous outputs in one run:
//
//	kensa check -H prod-01 -u admin --sudo \
//	    -o json -o csv:results.csv -o oscal:assessment.json
//
// reads to: emit JSON to stdout, write CSV to results.csv, write OSCAL
// Assessment Results to assessment.json — all from a single in-memory
// scan result, fanned out concurrently (C-019).
package output

import (
	"errors"
	"fmt"
	"strings"
)

// Spec is one parsed `--output FORMAT[:PATH]` argument.
//
// Path is the empty string when the format should be written to stdout
// (i.e., the caller passed `--output json` with no `:path` suffix, or
// the Unix-convention alias `--output json:-`). When non-empty, Path
// is the destination file the format will be written to (file is
// created or overwritten by the writer).
//
// Spec is a comparable value type — both fields are strings — so
// Specs can be used as map keys (e.g., to dedup operator-supplied
// outputs) and compared with ==. Adding a non-comparable field
// (slice, map, function) is a breaking change.
type Spec struct {
	// Format is the lowercase format identifier (e.g., "json",
	// "jsonl", "csv", "pdf", "evidence", "oscal", "markdown",
	// "text"). Always one of the values returned by KnownFormats.
	Format string
	// Path is the destination file, or "" for stdout.
	Path string
}

// String renders the Spec back to its argv form: "format" or
// "format:path". Useful for diagnostics and round-trip tests.
func (s Spec) String() string {
	if s.Path == "" {
		return s.Format
	}
	return s.Format + ":" + s.Path
}

// Errors returned by Parse.

// ErrEmptyFormat is returned when the input has no format component
// (e.g., "" or ":foo.json"). The error wraps a usage-style message
// so callers can present it to the operator.
var ErrEmptyFormat = errors.New("output: format is required (e.g. 'json' or 'json:report.json')")

// ErrUnknownFormat is returned when the format is not in the
// known-format registry. Wrap with the offending input to give the
// operator the bad value back.
var ErrUnknownFormat = errors.New("output: unknown format")

// ErrEmptyPath is returned for "format:" with a colon but no path
// (e.g., "json:"). Empty paths are explicit operator typos rather
// than a valid request to write to stdout — the operator should
// drop the colon to mean stdout.
var ErrEmptyPath = errors.New("output: path is empty after ':' (omit the colon to write to stdout)")

// ErrPathRequired is returned when a format that cannot reasonably
// be written to a TTY (currently just "pdf") is parsed without a
// path. Catching this at parse time prevents a binary blob from
// being emitted to the operator's terminal.
var ErrPathRequired = errors.New("output: this format requires a path (e.g. 'pdf:report.pdf')")

// Parse converts a single `--output` argument value into a Spec.
//
// Accepted input shapes:
//
//	"json"               → Spec{Format:"json", Path:""}
//	"json:report.json"   → Spec{Format:"json", Path:"report.json"}
//	"oscal:/var/log/x.json" → Spec{Format:"oscal", Path:"/var/log/x.json"}
//	"json:-"             → Spec{Format:"json", Path:""}  (Unix stdout alias)
//
// Rejected:
//
//	""                   → ErrEmptyFormat
//	":foo"               → ErrEmptyFormat
//	"json:"              → ErrEmptyPath
//	"unknown-format"     → ErrUnknownFormat (wrapped)
//	"unknown-fmt:foo"    → ErrUnknownFormat (wrapped)
//	"pdf"                → ErrPathRequired (binary format must have a destination file)
//
// Format names are normalized to lowercase before lookup so callers
// can pass "JSON" or "Json" without issue. The operator's original
// (pre-lowercase) format substring is echoed back in error messages
// so they see what they actually typed.
//
// Parse performs no whitespace trimming on either component:
// "json:foo " parses to Path:"foo " (with the trailing space embedded).
// Callers wanting a trim policy must apply it before calling.
func Parse(s string) (Spec, error) {
	if s == "" {
		return Spec{}, ErrEmptyFormat
	}

	// Split on the first ':' — paths may legitimately contain ':'
	// (URLs as paths, time-stamped subdirectories, etc.), but kensa
	// is Linux-only so the first colon is always the separator.
	rawFormat, path, hasColon := strings.Cut(s, ":")
	format := strings.ToLower(rawFormat)

	if format == "" {
		return Spec{}, ErrEmptyFormat
	}
	if hasColon && path == "" {
		return Spec{}, ErrEmptyPath
	}
	if !IsKnownFormat(format) {
		return Spec{}, fmt.Errorf("%w: %q (known: %s)", ErrUnknownFormat, rawFormat, strings.Join(KnownFormats(), ", "))
	}

	// Unix convention: a path of "-" means stdout. Normalize so
	// downstream writers don't have to special-case the marker
	// (and so they don't accidentally create a file named "-").
	if path == "-" {
		path = ""
	}

	if FormatRequiresPath(format) && path == "" {
		return Spec{}, fmt.Errorf("%w: %q", ErrPathRequired, rawFormat)
	}

	return Spec{Format: format, Path: path}, nil
}

// ParseAll converts a slice of --output values (e.g., from
// pflag.StringSliceP) into Specs, returning the first parse error
// if any value is invalid. Order is preserved — the same order the
// operator passed them on the command line, which is the order the
// fan-out (C-019) will run them in for deterministic output.
//
// Fail-fast: ParseAll returns on the first invalid value rather than
// collecting all errors. Callers wanting all errors at once should
// iterate and call Parse directly.
func ParseAll(values []string) ([]Spec, error) {
	specs := make([]Spec, 0, len(values))
	for i, v := range values {
		spec, err := Parse(v)
		if err != nil {
			return nil, fmt.Errorf("output[%d]: %w", i, err)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

// IsKnownFormat reports whether name is a registered output format.
// Lookup is case-insensitive; callers don't need to lowercase first.
func IsKnownFormat(name string) bool {
	_, ok := knownFormats[strings.ToLower(name)]
	return ok
}

// KnownFormats returns the registered format names in a stable order.
// Used by error messages and operator-facing help text. The returned
// slice is a fresh copy; mutating it does not affect the registry.
func KnownFormats() []string {
	out := make([]string, 0, len(knownFormatsOrder))
	out = append(out, knownFormatsOrder...)
	return out
}

// FormatRequiresPath reports whether the given format must be written
// to a file (path required) vs. accepting stdout when path is "".
// Currently only "pdf" requires a path because PDF output is a binary
// blob that doesn't render usefully on a terminal.
//
// Parse calls this internally to reject path-less invocations of
// path-required formats, so most callers don't need to invoke it
// themselves. It remains exported for help-text generation that
// wants to indicate "this format needs a destination."
//
// TODO(C-012): once the Writer interface lands, the path-required
// property should move onto the writer registration so adding a new
// format doesn't require editing this switch.
func FormatRequiresPath(format string) bool {
	switch strings.ToLower(format) {
	case "pdf":
		return true
	}
	return false
}

// knownFormats is the registry of accepted format names. The empty
// struct values are placeholders. C-012 will likely change the value
// type to a writer constructor (e.g., func() Writer); the public API
// of IsKnownFormat and KnownFormats is shaped to remain unchanged.
//
// Format vocabulary per docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md §6.2:
//
//	text       human-readable default (default for most subcommands)
//	json       structured JSON object
//	jsonl      newline-delimited JSON (NDJSON) — kensa-go addition
//	csv        comma-separated values for spreadsheet ingestion
//	pdf        binary PDF report (path required)
//	evidence   signed-envelope JSON (per TRANSACTION_CONTRACT_V1.md)
//	oscal      OSCAL Assessment Results JSON — kensa-go addition
//	markdown   GitHub-flavored Markdown (used by `kensa plan`)
var knownFormats = map[string]struct{}{
	"text":     {},
	"json":     {},
	"jsonl":    {},
	"csv":      {},
	"pdf":      {},
	"evidence": {},
	"oscal":    {},
	"markdown": {},
}

// knownFormatsOrder mirrors knownFormats but in display order for
// error messages and help text. Maps in Go don't have stable iteration
// order, so this slice is the source of truth for "what we tell the
// operator the available formats are." A test enforces that
// knownFormats and knownFormatsOrder stay in sync in both directions.
var knownFormatsOrder = []string{
	"text", "json", "jsonl", "csv", "pdf", "evidence", "oscal", "markdown",
}
