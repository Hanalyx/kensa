package progress

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Hanalyx/kensa/api"
)

// StreamConsumer renders a live stream of [Update]s to an io.Writer as each
// Update arrives. It implements [Sink], so a progress source delivers Updates
// to it incrementally; the consumer renders each one at the moment it is
// received and never buffers until an end-of-stream signal.
//
// A StreamConsumer is display-only and lossy-tolerant. It renders the stream
// and nothing else: the final summary — counts, exit code, any -o FILE
// serialization — is produced from the canonical ScanResult / RemediationResult
// struct by the output writers, never reconstructed from the rendered stream.
//
// The consumer writes ONLY to the io.Writer supplied at construction. The CLI
// points that writer at stderr or a dedicated --stream-file; the consumer never
// references os.Stdout itself (stdout is reserved for the canonical result).
// A write error from the underlying writer is swallowed: progress is cosmetic
// and strictly subordinate to the result path, so a failing terminal or a
// closed stream file must not panic or abort the run.
type StreamConsumer struct {
	w      io.Writer
	render func(io.Writer, Update)
	// txnDone counts the terminal per-rule Updates (TxnDone) this consumer
	// has rendered. The CLI reads it via TxnDoneCount and compares it against
	// the authoritative RemediationResult to detect completion events the
	// lossy engine bus dropped (spec progress-renderer C-08). It is a
	// display-side observation ONLY — never used to reconstruct or alter the
	// canonical result. The consumer is driven by a single goroutine (the
	// drain loop / the inventory renderer), so a plain int needs no lock.
	txnDone int
}

// NewTextConsumer returns a [StreamConsumer] that renders each [Update] as a
// human-readable line to w. TTY-awareness is INJECTED via isTTY rather than
// probed from a real terminal, so both the interactive (isTTY=true) and the
// plain/piped/CI (isTTY=false) formatting branches are deterministically
// unit-testable. The caller owns w and points it at stderr (or a stream file);
// the consumer never writes to stdout.
func NewTextConsumer(w io.Writer, isTTY bool) *StreamConsumer {
	// inPlace holds the carriage-return rewrite state for the isTTY in-place
	// mode (PR7 polish): true once a transient line has been written without a
	// trailing newline, so the next line knows to clear it first. It is closed
	// over by the render func and only ever touched by the single rendering
	// goroutine, so no lock is needed. When isTTY=false the closure renders the
	// plain, byte-identical-to-PR3 form and never sets inPlace.
	pending := &inPlaceState{}
	return &StreamConsumer{
		w: w,
		render: func(w io.Writer, u Update) {
			renderText(w, u, isTTY, pending)
		},
	}
}

// inPlaceState carries the single-bit cursor state for in-place TTY rendering:
// whether the writer currently holds a transient line that was emitted without
// a trailing newline (and so must be cleared before the next write).
type inPlaceState struct {
	dirty bool
}

// NewEventsJSONLConsumer returns a [StreamConsumer] that renders each [Update]
// as one compact, newline-terminated JSON object (NDJSON) to w. This is the
// machine-readable event stream; it is DISTINCT from the "jsonl" --output result
// format and is deliberately named events-jsonl. The caller owns w and points
// it at stderr or a --stream-file; the consumer never writes to stdout.
func NewEventsJSONLConsumer(w io.Writer) *StreamConsumer {
	return &StreamConsumer{w: w, render: renderEventsJSONL}
}

// Update renders u to the consumer's writer. It satisfies [Sink].
func (c *StreamConsumer) Update(u Update) {
	if c == nil || c.w == nil || c.render == nil {
		return
	}
	if u.Kind == TxnDone {
		c.txnDone++
	}
	c.render(c.w, u)
}

// TxnDoneCount reports how many TxnDone Updates this consumer has rendered. The
// CLI compares it against the authoritative RemediationResult to surface how
// many transaction-completion events the lossy engine bus dropped (spec
// progress-renderer C-08, cli-remediate-stream C-07). It is a display-side
// observation: it never feeds back into the canonical result, exit code, or any
// -o FILE serialization. A nil consumer (progress off) reports zero.
func (c *StreamConsumer) TxnDoneCount() int {
	if c == nil {
		return 0
	}
	return c.txnDone
}

// kindToken maps a [Kind] to a stable lower-case string token used in the
// events-jsonl stream and in text rendering. A token (not the raw int enum)
// keeps the machine-readable stream stable across reorderings of the Kind
// constants.
func kindToken(k Kind) string {
	switch k {
	case ScanStart:
		return "scan_start"
	case RuleChecked:
		return "rule_checked"
	case ProbeDone:
		return "probe_done"
	case TxnStarted:
		return "txn_started"
	case TxnPhase:
		return "txn_phase"
	case TxnDone:
		return "txn_done"
	case ScanEnd:
		return "scan_end"
	default:
		return "unset"
	}
}

// okMark renders the OK flag as a short human glyph for text output.
func okMark(ok bool) string {
	if ok {
		return "ok"
	}
	return "FAIL"
}

// ANSI clear-from-cursor-to-end-of-line. Emitted after a leading carriage
// return in in-place mode so a shorter line fully overwrites a longer previous
// one (otherwise the tail of the old line would linger on screen).
const clearToEOL = "\x1b[K"

// isTransientKind reports whether a Kind is a high-frequency per-item update
// that the in-place TTY mode rewrites in place (overwriting the previous such
// line) rather than committing with a newline. Per-rule checks and per-phase
// transaction updates are transient; scan/probe/transaction milestones are
// committed so they stay on screen.
func isTransientKind(k Kind) bool {
	return k == RuleChecked || k == TxnPhase
}

// renderText writes one human-readable line per Update. isTTY selects the
// interactive form; both branches always emit a line so the non-TTY path is
// never silent (and is unit-testable).
//
// In the isTTY in-place mode (PR7 polish), transient Updates (RuleChecked,
// TxnPhase) are written with a leading carriage return + clear-to-EOL and NO
// trailing newline, so each successive transient line overwrites the previous
// one in place; milestone/terminal Updates first clear any pending in-place
// line, then commit their own line with a trailing newline so it stays on
// screen. When isTTY=false the output is byte-identical to the pre-PR7 plain
// form: one '\n'-terminated line per Update, no carriage return, no escape
// sequence (so piped/CI logs are unchanged). pending carries the single-bit
// cursor state between calls.
func renderText(w io.Writer, u Update, isTTY bool, pending *inPlaceState) {
	// host: prefix only when set; the single-host CLI may leave it empty.
	host := ""
	if u.Host != "" {
		host = u.Host + ": "
	}

	var line string
	switch u.Kind {
	case ScanStart:
		line = fmt.Sprintf("%sscan start (%d rules)", host, u.Total)
	case RuleChecked:
		line = fmt.Sprintf("%s[%d/%d] checked %s %s", host, u.Index, u.Total, u.RuleID, okMark(u.OK))
		if u.Detail != "" {
			line += " (" + u.Detail + ")"
		}
	case ProbeDone:
		line = fmt.Sprintf("%sprobe %s %s", host, u.Detail, okMark(u.OK))
	case TxnStarted:
		line = fmt.Sprintf("%sremediate %s: started", host, u.RuleID)
	case TxnPhase:
		line = fmt.Sprintf("%sremediate %s: phase %s %s", host, u.RuleID, string(u.Phase), okMark(u.OK))
	case TxnDone:
		line = fmt.Sprintf("%sremediate %s: done %s", host, u.RuleID, okMark(u.OK))
		if u.Detail != "" {
			line += " (" + u.Detail + ")"
		}
	case ScanEnd:
		line = fmt.Sprintf("%sscan end (%d rules)", host, u.Total)
	default:
		line = fmt.Sprintf("%s%s", host, kindToken(u.Kind))
	}

	if !isTTY {
		// Plain mode: byte-identical to PR3 — one newline-terminated line per
		// Update, no carriage return, no escape sequence. pending is never
		// consulted or set in this branch. Write error swallowed: progress
		// must never break the run.
		_, _ = io.WriteString(w, line+"\n")
		return
	}

	// Interactive form: a leading marker distinguishes live progress from the
	// canonical result that lands on stdout.
	line = "› " + line

	if isTransientKind(u.Kind) {
		// Transient: rewrite in place. Leading CR returns the cursor to column
		// zero, clearToEOL wipes the prior (possibly longer) line, and no
		// trailing newline leaves the cursor parked for the next overwrite.
		_, _ = io.WriteString(w, "\r"+clearToEOL+line)
		pending.dirty = true
		return
	}

	// Milestone/terminal: if a transient line is pending on the current row,
	// clear it (CR + clearToEOL) before committing this line so the two do not
	// concatenate. Then commit with a trailing newline so the line persists.
	if pending.dirty {
		_, _ = io.WriteString(w, "\r"+clearToEOL)
		pending.dirty = false
	}
	_, _ = io.WriteString(w, line+"\n")
}

// eventLine is the NDJSON shape emitted per Update. Field names are stable and
// snake_case; kind is the string token, not the raw enum int. phase reuses the
// api phase string vocabulary.
type eventLine struct {
	Host   string    `json:"host"`
	Kind   string    `json:"kind"`
	RuleID string    `json:"rule_id"`
	Index  int       `json:"index"`
	Total  int       `json:"total"`
	OK     bool      `json:"ok"`
	Phase  api.Phase `json:"phase"`
	Detail string    `json:"detail"`
}

// renderEventsJSONL writes one compact, newline-terminated JSON object for u.
func renderEventsJSONL(w io.Writer, u Update) {
	rec := eventLine{
		Host:   u.Host,
		Kind:   kindToken(u.Kind),
		RuleID: u.RuleID,
		Index:  u.Index,
		Total:  u.Total,
		OK:     u.OK,
		Phase:  u.Phase,
		Detail: u.Detail,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		// Marshaling a fixed-shape struct of primitives cannot realistically
		// fail; guard anyway and stay silent rather than break the run.
		return
	}
	b = append(b, '\n')
	// Write error is intentionally swallowed: progress must never break the run.
	_, _ = w.Write(b)
}
