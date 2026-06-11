package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/progress"
)

// ANSI SGR codes used by the streaming row renderer. Emitted only when
// color is enabled (stdout is a TTY); otherwise rows are plain text.
const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "\x1b[1m"
	sgrGreen  = "\x1b[32m"
	sgrRed    = "\x1b[31m"
	sgrYellow = "\x1b[33m"
	sgrDim    = "\x1b[2m"
)

// StreamScanWriter renders a scan's results incrementally — one aligned row
// per rule, in scan order, printed as each rule completes — matching the
// row-by-row live style of the reference (Python) kensa. Column order:
//
//	STATUS  SEVERITY  RULE-ID  DESCRIPTION [detail]
//
// It implements [progress.Sink]: the scan Runner drives it via
// scan.WithProgress, so each row appears the instant its rule's check
// finishes rather than being buffered to the end. The canonical result is
// still the returned [api.ScanResult]; these rows are the human rendering of
// it, not a separate progress channel — so they go to the result stream
// (stdout), never stderr.
type StreamScanWriter struct {
	w     io.Writer
	color bool
	byID  map[string]*api.Rule

	pass    int
	fixed   int
	fail    int
	errored int
	skipped int
}

// NewStreamScanWriter builds a writer over w. color enables ANSI styling
// (caller passes stdout-is-a-TTY). rules supplies the title/severity for each
// rule id the scan reports.
func NewStreamScanWriter(w io.Writer, color bool, rules []*api.Rule) *StreamScanWriter {
	byID := make(map[string]*api.Rule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}
	return &StreamScanWriter{w: w, color: color, byID: byID}
}

// Banner prints the host-identification rule and platform label, before any
// rows. Mirrors the reference layout: a centered "──── Host: <host> ────"
// rule then a "Platform:" line — the OS appears only on the Platform line,
// not embedded in the rule.
func (s *StreamScanWriter) Banner(host, osLabel string) {
	const width = 64
	title := "Host: " + host
	dashes := width - len(title) - 2 // spaces around the title
	if dashes < 6 {
		dashes = 6
	}
	left := dashes / 2
	right := dashes - left
	rule := strings.Repeat("─", left) + " " + s.paint(sgrBold, title) + " " + strings.Repeat("─", right)
	fmt.Fprintln(s.w, rule)
	if osLabel != "" {
		fmt.Fprintf(s.w, "  Platform: %s\n", osLabel)
	}
}

// Update implements [progress.Sink]. It renders one row per RuleChecked
// update. Non-rule updates are ignored.
func (s *StreamScanWriter) Update(u progress.Update) {
	if u.Kind != progress.RuleChecked {
		return
	}

	rule := s.byID[u.RuleID]
	title := u.RuleID
	severity := ""
	if rule != nil {
		if rule.Title != "" {
			title = rule.Title
		}
		severity = rule.Severity
	}

	var statusCell string
	switch {
	case u.Skipped:
		s.skipped++
		statusCell = s.status("SKIP", sgrDim)
	case u.Errored:
		s.errored++
		statusCell = s.status("ERROR", sgrRed)
	case u.Fixed:
		s.fixed++
		statusCell = s.status("FIXED", sgrGreen)
	case u.OK:
		s.pass++
		statusCell = s.status("PASS", sgrGreen)
	default:
		s.fail++
		statusCell = s.status("FAIL", sgrRed)
	}

	detail := ""
	if !u.OK && u.Detail != "" {
		detail = "  " + s.paint(sgrDim, u.Detail)
	}

	// STATUS(5)  SEVERITY(4)  RULE-ID(<=40, left)  DESCRIPTION  [detail]
	fmt.Fprintf(s.w, "  %s  %s  %-40s %s%s\n",
		statusCell, s.severity(severity), u.RuleID, title, detail)
}

// Summary prints the trailing tally line after all rows.
func (s *StreamScanWriter) Summary() {
	total := s.pass + s.fixed + s.fail + s.errored + s.skipped
	fmt.Fprintf(s.w, "\n  %s passed", s.paint(sgrGreen, fmt.Sprintf("%d", s.pass)))
	if s.fixed > 0 {
		fmt.Fprintf(s.w, ", %s fixed", s.paint(sgrGreen, fmt.Sprintf("%d", s.fixed)))
	}
	fmt.Fprintf(s.w, ", %s failed", s.failCount())
	if s.errored > 0 {
		fmt.Fprintf(s.w, ", %s errored", s.paint(sgrRed, fmt.Sprintf("%d", s.errored)))
	}
	if s.skipped > 0 {
		fmt.Fprintf(s.w, ", %s skipped", s.paint(sgrDim, fmt.Sprintf("%d", s.skipped)))
	}
	fmt.Fprintf(s.w, "  (of %d)\n", total)
}

func (s *StreamScanWriter) failCount() string {
	n := fmt.Sprintf("%d", s.fail)
	if s.fail > 0 {
		return s.paint(sgrRed, n)
	}
	return n
}

// status renders a status word padded to 5 visible columns, colored.
func (s *StreamScanWriter) status(word, code string) string {
	pad := ""
	if len(word) < 5 {
		pad = strings.Repeat(" ", 5-len(word))
	}
	return s.paint(code, word) + pad
}

// severity renders the 4-char severity badge with a level-appropriate color.
func (s *StreamScanWriter) severity(sev string) string {
	badge := severityBadge(sev)
	switch strings.ToLower(sev) {
	case "critical":
		return s.paint(sgrRed, badge)
	case "high":
		return s.paint(sgrYellow, badge)
	case "low":
		return s.paint(sgrDim, badge)
	}
	return badge // medium / unknown: plain
}

func (s *StreamScanWriter) paint(code, text string) string {
	if !s.color {
		return text
	}
	return code + text + sgrReset
}
