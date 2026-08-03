package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
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

// textScanWriter renders a ScanResult as a grouped failure-first
// operator-readable layout per the C-022 rewrite. Rendering body
// lives in renderScanResult (text_scan.go) so the writer struct
// stays a thin dispatch shim.
type textScanWriter struct{}

func (textScanWriter) Format() string { return "text" }

func (textScanWriter) WriteScanResult(w io.Writer, hostID string, rules []*api.Rule, result *api.ScanResult) error {
	return renderScanResult(w, hostID, rules, result, ScanRenderOptions{})
}

// textRemediationWriter renders a RemediationResult as a tabular listing
// with a committed/rolled-back/error/skipped tally footer.
type textRemediationWriter struct{}

func (textRemediationWriter) Format() string { return "text" }

func (textRemediationWriter) WriteRemediationResult(w io.Writer, hostID string, rules []*api.Rule, result *api.RemediationResult) error {
	// B6 (2026-05-13): split the "committed" count into
	// (a) already-compliant skips (scanner's pre-check
	// returned passed → no engine.Run, no store record)
	// and (b) actually-applied commits (engine.Run wrote a
	// transaction record). Pre-fix both were tallied under
	// "committed" — operators couldn't tell whether kensa
	// did real work or just verified state. The 2026-05-13
	// live test on 192.168.1.211 surfaced this: a 433-rule
	// "committed" summary against a 36-row history table.
	applied, alreadyCompliant, rolledBack, skipped, errs, staged := 0, 0, 0, 0, 0, 0
	if _, err := fmt.Fprintf(w, "Remediation results for %s:\n\n", hostID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  %-40s  %-20s\n", "RULE", "STATUS"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  "+strings.Repeat("-", 65)); err != nil {
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
			if isAlreadyCompliantSkip(&txr) {
				alreadyCompliant++
				status = "already-compliant"
			} else {
				applied++
				status = "applied"
			}
		case api.StatusRolledBack:
			rolledBack++
		case api.StatusStaged:
			staged++
			status = "staged (reboot required)"
		case api.StatusErrored:
			errs++
			if txr.Error != nil {
				status = "errored: " + truncate(txr.Error.Error(), 30)
			}
		default:
			skipped++
		}
		if _, err := fmt.Fprintf(w, "  %-40s  %-20s\n", truncate(ruleID, 40), status); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "\n  %d applied, %d already-compliant, %d staged (reboot required), %d rolled_back, %d errors, %d skipped\n",
		applied, alreadyCompliant, staged, rolledBack, errs, skipped)
	return err
}

// isAlreadyCompliantSkip reports whether the given TransactionResult is the
// scanner's "rule already passed pre-check; nothing to apply" record. These
// records are in-memory only — they are NOT persisted by the engine (no apply
// ran), so an operator inspecting kensa history won't see them. The summary
// count splits them out so the operator can distinguish "kensa did work" from
// "kensa verified state."
//
// This used to derive the fact by pattern-matching the record's shape: exactly
// one StepResult with Mechanism="check" and Detail containing the substring
// "already in desired state". That is the same workaround an external consumer
// would have to write, living inside Kensa, and it breaks the moment anyone
// rewords a human-readable Detail string. [api.TransactionResult.AlreadyCompliant]
// publishes the fact instead, so nobody has to guess at it.
//
// The shape check is retained as belt-and-braces for a result built by a code
// path that has not been updated to set the field. It is NOT, as an earlier
// version of this comment claimed, a decode path for older Kensa results:
// internal/output is unreachable by external consumers, WriteRemediationResult
// is called only from cmd/kensa with an in-process value, and nothing in the
// tree unmarshals JSON into a RemediationResult. Giving dead code a false
// reason to exist tells the next maintainer that the fragile string coupling
// this change removed is load-bearing.
func isAlreadyCompliantSkip(txr *api.TransactionResult) bool {
	if txr.AlreadyCompliant {
		return true
	}
	if len(txr.Steps) != 1 {
		return false
	}
	s := txr.Steps[0]
	return s.Mechanism == "check" && strings.Contains(s.Detail, "already in desired state")
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
// The function is package-private because it is a presentation
// helper for the text writers; callers outside the package should
// not depend on its specific clipping rule.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
