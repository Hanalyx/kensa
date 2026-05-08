package output

import (
	"fmt"
	"io"
	"time"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/breakline"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"
)

// PDF rendering uses the maroto v2 high-level layout DSL on top of
// gofpdf. Selected per founder ratification on 2026-05-08 (C-014):
// MIT-licensed, pure Go (no cgo, no glibc dependency — preserves the
// CGO_ENABLED=0 + -tags netgo build discipline), with built-in row
// and column primitives that fit compliance-report layouts.
//
// We avoid maroto's higher-level "list" component because it requires
// the row content to be a generic collection type, which forces an
// extra reflection step. Direct row construction with text columns
// is simpler and produces identical output.

// pdfRowHeight is the height (in maroto layout units) of a single
// data row. 16 accommodates a two-line wrap of long rule IDs.
//
// Real SCAP rule IDs commonly run 75–95 characters
// (xccdf_org.ssgproject.content_rule_… style) with no embedded
// whitespace. Maroto's default break strategy is EmptySpaceStrategy
// which can only break at spaces, so a no-space rule ID would
// overflow horizontally into adjacent columns. The rule cell
// explicitly uses breakline.DashStrategy (character-level breaks
// with a hyphen) — see addScanReportContent / addRemediationReportContent.
//
// 16 fits two lines at font size 8 (line height ~7) plus padding;
// rule IDs longer than ~50 characters wrap to a second line; very
// long IDs (>~100 chars) still wrap into the column rather than
// overflowing into STATUS / DETAIL.
const pdfRowHeight = 16

// pdfHeaderHeight is the height of the table-header row. Bumped vs
// data rows so the bold header text breathes.
const pdfHeaderHeight = 9

// pdfTitleHeight is the height of the report title row.
const pdfTitleHeight = 12

// pdfSummaryHeight is the height of the per-result summary line
// (e.g., "Host: 192.168.1.211 — 87 passed, 3 failed, 0 errors").
const pdfSummaryHeight = 8

// pdfStatusColWidth and pdfRuleColWidth are the maroto column-grid
// widths (out of 12) for the status and rule-ID columns. Detail
// gets the rest.
const (
	pdfRuleColWidth   = 5
	pdfStatusColWidth = 2
	pdfDetailColWidth = 5
)

// pdfScanWriter renders a ScanResult as a PDF compliance report.
// Layout: title → host summary → table (rule, status, detail).
//
// PDF is binary output; per output.Parse the format requires a path
// (ErrPathRequired) so the writer is never invoked with a TTY
// destination. Each WriteScanResult call produces a complete PDF
// document.
type pdfScanWriter struct{}

func (pdfScanWriter) Format() string { return "pdf" }

func (p pdfScanWriter) WriteScanResult(w io.Writer, hostID string, rules []*api.Rule, result *api.ScanResult) error {
	m := maroto.New()
	if err := addScanReportContent(m, hostID, rules, result); err != nil {
		return err
	}
	return generateAndWrite(m, w)
}

func addScanReportContent(m core.Maroto, hostID string, rules []*api.Rule, result *api.ScanResult) error {
	pass, fail, errs := scanCounts(result)
	m.AddRows(
		titleRow("kensa scan report"),
		summaryRow(fmt.Sprintf("Host: %s — %d passed, %d failed, %d errors  (generated %s)",
			hostID, pass, fail, errs, time.Now().UTC().Format(time.RFC3339))),
	)
	m.AddRow(pdfHeaderHeight, headerCols("RULE", "STATUS", "DETAIL")...)
	for i, txr := range result.Transactions {
		ruleID := ""
		if i < len(rules) {
			ruleID = rules[i].ID
		}
		status, detail := scanStatusAndDetail(txr)
		m.AddRow(pdfRowHeight,
			text.NewCol(pdfRuleColWidth, ruleID, ruleCellProps()),
			text.NewCol(pdfStatusColWidth, status, props.Text{Size: 8, Style: fontstyle.Bold, Align: align.Center}),
			text.NewCol(pdfDetailColWidth, detail, props.Text{Size: 8, BreakLineStrategy: breakline.DashStrategy}),
		)
	}
	return nil
}

// ruleCellProps returns the text properties for the rule-ID cell.
// The DashStrategy break policy ensures long no-space SCAP rule IDs
// (xccdf_org.ssgproject.content_rule_…) wrap with a hyphen at
// character boundaries instead of overflowing the column.
func ruleCellProps() props.Text {
	return props.Text{
		Size:              8,
		BreakLineStrategy: breakline.DashStrategy,
	}
}

func scanCounts(result *api.ScanResult) (pass, fail, errs int) {
	for _, txr := range result.Transactions {
		switch txr.Status {
		case api.StatusCommitted:
			pass++
		case api.StatusErrored:
			errs++
		default:
			fail++
		}
	}
	return
}

func scanStatusAndDetail(txr api.TransactionResult) (status, detail string) {
	switch txr.Status {
	case api.StatusCommitted:
		status = "PASS"
	case api.StatusErrored:
		status = "ERROR"
		if txr.Error != nil {
			detail = txr.Error.Error()
		}
	default:
		status = "FAIL"
	}
	if detail == "" && len(txr.Steps) > 0 {
		detail = txr.Steps[0].Detail
	}
	return
}

// pdfRemediationWriter renders a RemediationResult as a PDF
// compliance report. Same layout shape as scan, but the status
// column preserves the raw API vocabulary (committed / rolled_back /
// partially_applied / errored) since auditors of remediation runs
// need that distinction.
type pdfRemediationWriter struct{}

func (pdfRemediationWriter) Format() string { return "pdf" }

func (p pdfRemediationWriter) WriteRemediationResult(w io.Writer, hostID string, rules []*api.Rule, result *api.RemediationResult) error {
	m := maroto.New()
	if err := addRemediationReportContent(m, hostID, rules, result); err != nil {
		return err
	}
	return generateAndWrite(m, w)
}

func addRemediationReportContent(m core.Maroto, hostID string, rules []*api.Rule, result *api.RemediationResult) error {
	committed, rolledBack, partial, errs := remediationCounts(result)
	m.AddRows(
		titleRow("kensa remediation report"),
		summaryRow(fmt.Sprintf("Host: %s — %d committed, %d rolled_back, %d partially_applied, %d errors  (generated %s)",
			hostID, committed, rolledBack, partial, errs, time.Now().UTC().Format(time.RFC3339))),
	)
	m.AddRow(pdfHeaderHeight, headerCols("RULE", "STATUS", "DETAIL")...)
	for i, txr := range result.Transactions {
		ruleID := ""
		if i < len(rules) {
			ruleID = rules[i].ID
		}
		status := string(txr.Status)
		detail := ""
		if txr.Error != nil {
			detail = txr.Error.Error()
		} else if len(txr.Steps) > 0 {
			detail = txr.Steps[0].Detail
		}
		m.AddRow(pdfRowHeight,
			text.NewCol(pdfRuleColWidth, ruleID, ruleCellProps()),
			text.NewCol(pdfStatusColWidth, status, props.Text{Size: 8, Style: fontstyle.Bold, Align: align.Center}),
			text.NewCol(pdfDetailColWidth, detail, props.Text{Size: 8, BreakLineStrategy: breakline.DashStrategy}),
		)
	}
	return nil
}

func remediationCounts(result *api.RemediationResult) (committed, rolledBack, partial, errs int) {
	for _, txr := range result.Transactions {
		switch txr.Status {
		case api.StatusCommitted:
			committed++
		case api.StatusRolledBack:
			rolledBack++
		case api.StatusErrored:
			errs++
		case api.StatusPartiallyApplied:
			partial++
		}
	}
	return
}

// titleRow returns a centered, bold, large title row.
func titleRow(s string) core.Row {
	return row.New(pdfTitleHeight).Add(
		text.NewCol(12, s, props.Text{
			Size:  16,
			Style: fontstyle.Bold,
			Align: align.Center,
		}),
	)
}

// summaryRow returns a single-line summary row.
func summaryRow(s string) core.Row {
	return row.New(pdfSummaryHeight).Add(
		text.NewCol(12, s, props.Text{Size: 9, Align: align.Left}),
	)
}

// headerCols builds three bold, centered text columns for the table
// header row. Widths line up with pdfRuleColWidth / pdfStatusColWidth /
// pdfDetailColWidth so data rows align with their headers.
func headerCols(rule, status, detail string) []core.Col {
	hdr := props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}
	return []core.Col{
		text.NewCol(pdfRuleColWidth, rule, hdr),
		text.NewCol(pdfStatusColWidth, status, hdr),
		text.NewCol(pdfDetailColWidth, detail, hdr),
	}
}

// generateAndWrite finalizes the maroto document and copies its
// bytes to w. Maroto's Generate() returns a core.Document whose
// GetBytes() yields the complete PDF. Errors are surfaced from
// either Generate or the underlying io.Writer.
func generateAndWrite(m core.Maroto, w io.Writer) error {
	doc, err := m.Generate()
	if err != nil {
		return fmt.Errorf("pdf: generate: %w", err)
	}
	_, err = w.Write(doc.GetBytes())
	return err
}

// Compile-time interface assertions: catch a regression where a
// method receiver type drifts from value to pointer or a method
// signature changes incompatibly.
var (
	_ ScanResultWriter        = pdfScanWriter{}
	_ RemediationResultWriter = pdfRemediationWriter{}
)
