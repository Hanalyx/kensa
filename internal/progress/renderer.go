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
}

// NewTextConsumer returns a [StreamConsumer] that renders each [Update] as a
// human-readable line to w. TTY-awareness is INJECTED via isTTY rather than
// probed from a real terminal, so both the interactive (isTTY=true) and the
// plain/piped/CI (isTTY=false) formatting branches are deterministically
// unit-testable. The caller owns w and points it at stderr (or a stream file);
// the consumer never writes to stdout.
func NewTextConsumer(w io.Writer, isTTY bool) *StreamConsumer {
	return &StreamConsumer{
		w: w,
		render: func(w io.Writer, u Update) {
			renderText(w, u, isTTY)
		},
	}
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
	c.render(c.w, u)
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

// renderText writes one human-readable line per Update. isTTY selects a
// slightly richer interactive form; both branches always emit a line so the
// non-TTY path is never silent (and is unit-testable).
func renderText(w io.Writer, u Update, isTTY bool) {
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

	if isTTY {
		// Interactive form: a leading marker distinguishes live progress
		// from the canonical result that lands on stdout. Kept on its own
		// line (no in-place carriage-return rewrite — that is PR7 polish).
		line = "› " + line
	}
	// Write error is intentionally swallowed: progress must never break the run.
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
