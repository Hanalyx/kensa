package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// textCapsWriter renders a CapabilitySet as a sorted check/cross list.
type textCapsWriter struct{}

func (textCapsWriter) Format() string { return "text" }

func (textCapsWriter) WriteCaps(w io.Writer, hostID string, caps api.CapabilitySet) error {
	names := make([]string, 0, len(caps))
	for k := range caps {
		names = append(names, k)
	}
	sort.Strings(names)
	if _, err := fmt.Fprintf(w, "Capabilities for %s:\n", hostID); err != nil {
		return err
	}
	for _, name := range names {
		mark := "✗"
		if caps[name] {
			mark = "✓"
		}
		if _, err := fmt.Fprintf(w, "  %s  %s\n", mark, name); err != nil {
			return err
		}
	}
	return nil
}

// textScanWriter renders a ScanResult as a tabular per-rule listing
// with a pass/fail/error tally footer.
type textScanWriter struct{}

func (textScanWriter) Format() string { return "text" }

func (textScanWriter) WriteScanResult(w io.Writer, hostID string, rules []*api.Rule, result *api.ScanResult) error {
	pass, fail, errs := 0, 0, 0
	if _, err := fmt.Fprintf(w, "Check results for %s:\n\n", hostID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  %-40s  %-10s  %s\n", "RULE", "STATUS", "DETAIL"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  "+strings.Repeat("-", 80)); err != nil {
		return err
	}
	for i, txr := range result.Transactions {
		ruleID := ""
		if i < len(rules) {
			ruleID = rules[i].ID
		}
		status := "PASS"
		switch txr.Status {
		case api.StatusErrored:
			status = "ERROR"
			errs++
		case api.StatusCommitted:
			pass++
		default:
			status = "FAIL"
			fail++
		}
		detail := ""
		if len(txr.Steps) > 0 {
			detail = truncate(txr.Steps[0].Detail, 50)
		}
		if txr.Error != nil {
			detail = truncate(txr.Error.Error(), 50)
		}
		if _, err := fmt.Fprintf(w, "  %-40s  %-10s  %s\n", truncate(ruleID, 40), status, detail); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "\n  %d passed, %d failed, %d errors\n", pass, fail, errs)
	return err
}

// textRemediationWriter renders a RemediationResult as a tabular listing
// with a committed/rolled-back/error/skipped tally footer.
type textRemediationWriter struct{}

func (textRemediationWriter) Format() string { return "text" }

func (textRemediationWriter) WriteRemediationResult(w io.Writer, hostID string, rules []*api.Rule, result *api.RemediationResult) error {
	committed, rolledBack, skipped, errs := 0, 0, 0, 0
	if _, err := fmt.Fprintf(w, "Remediation results for %s:\n\n", hostID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  %-40s  %-15s\n", "RULE", "STATUS"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  "+strings.Repeat("-", 60)); err != nil {
		return err
	}
	for i, txr := range result.Transactions {
		ruleID := ""
		if i < len(rules) {
			ruleID = rules[i].ID
		}
		status := string(txr.Status)
		switch txr.Status {
		case api.StatusCommitted:
			committed++
		case api.StatusRolledBack:
			rolledBack++
		case api.StatusErrored:
			errs++
			if txr.Error != nil {
				status = "errored: " + truncate(txr.Error.Error(), 30)
			}
		default:
			skipped++
		}
		if _, err := fmt.Fprintf(w, "  %-40s  %-15s\n", truncate(ruleID, 40), status); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "\n  %d committed, %d rolled_back, %d errors, %d skipped\n",
		committed, rolledBack, errs, skipped)
	return err
}

// textHistoryWriter renders a transaction list as a fixed-width table.
type textHistoryWriter struct{}

func (textHistoryWriter) Format() string { return "text" }

func (textHistoryWriter) WriteHistory(w io.Writer, txns []api.TransactionRecord) error {
	if _, err := fmt.Fprintf(w, "%-36s  %-15s  %-25s  %-15s  %s\n",
		"TRANSACTION-ID", "STATUS", "RULE", "HOST", "FINISHED"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, strings.Repeat("-", 105)); err != nil {
		return err
	}
	for _, t := range txns {
		if _, err := fmt.Fprintf(w, "%-36s  %-15s  %-25s  %-15s  %s\n",
			t.ID,
			t.Status,
			truncate(t.RuleID, 25),
			truncate(t.HostID, 15),
			t.FinishedAt.Format(time.RFC3339),
		); err != nil {
			return err
		}
	}
	return nil
}

// truncate clips s to at most n display columns. Strings longer than
// n are cut to n-1 with a single horizontal-ellipsis appended; this
// keeps table columns visually stable when rule IDs or detail strings
// are long enough to overflow.
//
// truncate is package-private because it is a presentation helper for
// the text writers; callers outside the package should not depend on
// its specific clipping rule.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
