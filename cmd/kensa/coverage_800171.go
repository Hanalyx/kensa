package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Hanalyx/kensa/internal/coverage"
	"github.com/Hanalyx/kensa/internal/output"
)

// scanCapabilities is the slice of a scan report this needs: the per-host
// capability map. Decoding only these fields keeps the command working against
// any scan report the engine has ever written, rather than coupling it to the
// full shape.
type scanCapabilities struct {
	Capabilities map[string]bool `json:"Capabilities"`
}

// runNIST800171Coverage answers "what share of the objectives a scanner can
// evidence does kensa cover", for NIST SP 800-171 Rev 2.
//
// It takes no --rules-dir. The numerator is reviewed mapping status, which
// travels in the embedded catalog, not scan posture and not the corpus on
// disk. A rule failing on a host says the host is non-compliant; it says
// nothing about whether kensa can evidence the objective, and letting scan
// results move this number would make a fleet of broken hosts look worse at
// compliance coverage than an identical fleet of healthy ones.
func runNIST800171Coverage(fromScan, format string, quiet bool) error {
	arch := coverage.ArchUnknown
	hosts := 0

	if fromScan != "" {
		raw, err := os.ReadFile(fromScan)
		if err != nil {
			return fmt.Errorf("--from-scan: %w", err)
		}
		caps, n, err := capabilitiesFromScan(raw)
		if err != nil {
			return WrapUsageError("--from-scan", err)
		}
		if n == 0 {
			return NewUsageError("--from-scan: no host capabilities in that report, " +
				"so the fleet's identity architecture cannot be determined")
		}
		arch = coverage.ArchitectureFromCapabilities(caps)
		hosts = n
	}

	report := coverage.ComputeNIST800171(arch, hosts)
	out := bodyOut(quiet)
	if format == "json" {
		jw, _ := output.JSONValueWriterFor("json")
		return jw.WriteJSONValue(out, report)
	}
	writeNIST800171Text(out, report)
	return nil
}

// capabilitiesFromScan accepts either a single scan report or an array of them,
// because an operator aggregating a fleet has both shapes to hand.
func capabilitiesFromScan(raw []byte) ([]map[string]bool, int, error) {
	var one scanCapabilities
	if err := json.Unmarshal(raw, &one); err == nil && one.Capabilities != nil {
		return []map[string]bool{one.Capabilities}, 1, nil
	}
	var many []scanCapabilities
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, 0, fmt.Errorf("not a scan report or an array of them: %w", err)
	}
	out := make([]map[string]bool, 0, len(many))
	for _, m := range many {
		if m.Capabilities != nil {
			out = append(out, m.Capabilities)
		}
	}
	return out, len(out), nil
}

// writeNIST800171Text renders the report.
//
// The layout exists to make the number unquotable on its own. The denominator
// and both excluded buckets are printed adjacent to the count, and the
// percentage is never rendered without them on the same line, because the
// interesting deception here is not a wrong number but a true one quoted
// without its boundary.
func writeNIST800171Text(w io.Writer, r coverage.NIST800171Report) {
	fmt.Fprintf(w, "NIST SP 800-171 Rev 2 objective coverage\n\n")

	pct := func(n, d int) string {
		if d == 0 {
			return "n/a"
		}
		return fmt.Sprintf("%.0f%%", 100*float64(n)/float64(d))
	}

	if r.Buckets == nil {
		fmt.Fprintf(w, "  No scan report supplied, so the fleet's identity architecture is\n")
		fmt.Fprintf(w, "  unknown and BOTH ceilings are shown. Pass --from-scan to get the\n")
		fmt.Fprintf(w, "  denominator for a specific fleet.\n\n")
		for _, a := range []coverage.Architecture{coverage.ArchLocalAccounts, coverage.ArchDirectoryJoined} {
			c := r.Ceilings[a]
			b := c.Buckets
			fmt.Fprintf(w, "  %-18s %d satisfied of %d assessable (%s)\n",
				a, c.Satisfied, b.Assessable, pct(c.Satisfied, b.Assessable))
			fmt.Fprintf(w, "  %-18s %d boundary, %d unclassified, %d total\n\n",
				"", b.Boundary, b.Unclassified, b.Total)
		}
	} else {
		b := *r.Buckets
		fmt.Fprintf(w, "  fleet architecture   %s (%d host(s) scanned)\n\n", r.Architecture, r.HostsScanned)
		fmt.Fprintf(w, "  satisfied            %d of %d assessable (%s)\n",
			r.Satisfied, b.Assessable, pct(r.Satisfied, b.Assessable))
		fmt.Fprintf(w, "  partial              %d   evidence with a stated gap\n", r.Partial)
		fmt.Fprintf(w, "  no rule              %d   assessable, nothing covers it yet\n\n", r.NoRule)
		fmt.Fprintf(w, "  assessable           %d   a host scanner can evidence these\n", b.Assessable)
		fmt.Fprintf(w, "  boundary             %d   no configuration scanner can, ours or anyone's\n", b.Boundary)
		fmt.Fprintf(w, "  unclassified         %d   nobody has decided which of the two\n", b.Unclassified)
		fmt.Fprintf(w, "  total                %d   the whole of Revision 2\n\n", b.Total)
	}

	if n := len(r.UnclassifiedIDs); n > 0 {
		fmt.Fprintf(w, "  %d objectives are unclassified and are counted in neither bucket.\n", n)
		fmt.Fprintf(w, "  They are not a gap in the product and not a boundary; nobody has\n")
		fmt.Fprintf(w, "  dispositioned them. First few: %v\n\n", firstN(r.UnclassifiedIDs, 6))
	}
	fmt.Fprintf(w, "  source digest        %s\n", short(r.SourceDigest))
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
