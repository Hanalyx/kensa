package progress_test

import (
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/progress"
)

// recordingSink records every Update it receives, exercising the Sink
// interface from a concrete implementation.
type recordingSink struct {
	got []progress.Update
}

func (r *recordingSink) Update(u progress.Update) { r.got = append(r.got, u) }

// TestKindConstantsDistinct verifies the progress milestones are all defined
// and mutually distinct.
//
// @spec progress-types
// @ac AC-01
func TestKindConstantsDistinct(t *testing.T) {
	t.Run("progress-types/AC-01", func(t *testing.T) {
		kinds := map[string]progress.Kind{
			"ScanStart":   progress.ScanStart,
			"RuleChecked": progress.RuleChecked,
			"ProbeDone":   progress.ProbeDone,
			"TxnStarted":  progress.TxnStarted,
			"TxnPhase":    progress.TxnPhase,
			"TxnDone":     progress.TxnDone,
			"ScanEnd":     progress.ScanEnd,
		}
		seen := map[progress.Kind]string{}
		for name, k := range kinds {
			if k == progress.KindUnset {
				t.Errorf("%s equals the zero value KindUnset", name)
			}
			if prev, ok := seen[k]; ok {
				t.Errorf("%s and %s share the same Kind value %d", name, prev, k)
			}
			seen[k] = name
		}
		if len(seen) != len(kinds) {
			t.Errorf("expected %d distinct kinds, got %d", len(kinds), len(seen))
		}
	})
}

// TestUpdateRoundTrips verifies an Update struct literal round-trips every
// field, including the api.Phase.
//
// @spec progress-types
// @ac AC-02
func TestUpdateRoundTrips(t *testing.T) {
	t.Run("progress-types/AC-02", func(t *testing.T) {
		u := progress.Update{
			Host:   "host-a",
			Kind:   progress.TxnPhase,
			RuleID: "rule-x",
			Index:  3,
			Total:  9,
			OK:     true,
			Detail: "apply ok",
			Phase:  api.PhaseApply,
		}
		if u.Host != "host-a" {
			t.Errorf("Host = %q, want %q", u.Host, "host-a")
		}
		if u.Kind != progress.TxnPhase {
			t.Errorf("Kind = %d, want %d", u.Kind, progress.TxnPhase)
		}
		if u.RuleID != "rule-x" {
			t.Errorf("RuleID = %q, want %q", u.RuleID, "rule-x")
		}
		if u.Index != 3 || u.Total != 9 {
			t.Errorf("Index/Total = %d/%d, want 3/9", u.Index, u.Total)
		}
		if !u.OK {
			t.Error("OK = false, want true")
		}
		if u.Detail != "apply ok" {
			t.Errorf("Detail = %q, want %q", u.Detail, "apply ok")
		}
		if u.Phase != api.PhaseApply {
			t.Errorf("Phase = %q, want %q", u.Phase, api.PhaseApply)
		}
	})
}

// TestSinkReceivesUpdate verifies a concrete Sink observes the exact Update
// delivered to its Update method.
//
// @spec progress-types
// @ac AC-03
func TestSinkReceivesUpdate(t *testing.T) {
	t.Run("progress-types/AC-03", func(t *testing.T) {
		var sink progress.Sink = &recordingSink{}
		want := progress.Update{Host: "h1", Kind: progress.RuleChecked, RuleID: "r1", Index: 1, Total: 2, OK: true}
		sink.Update(want)

		rec := sink.(*recordingSink)
		if len(rec.got) != 1 {
			t.Fatalf("recorded %d updates, want 1", len(rec.got))
		}
		if rec.got[0] != want {
			t.Errorf("recorded %+v, want %+v", rec.got[0], want)
		}
	})
}

// TestEmitNilSafe verifies Emit is a no-op on a nil Sink (no panic) and
// delivers to a non-nil Sink.
//
// @spec progress-types
// @ac AC-04
func TestEmitNilSafe(t *testing.T) {
	t.Run("progress-types/AC-04", func(t *testing.T) {
		u := progress.Update{Host: "h", Kind: progress.ScanStart, Total: 5}

		// Nil Sink: must not panic.
		var nilSink progress.Sink
		progress.Emit(nilSink, u) // no panic == pass

		// Non-nil Sink: must deliver.
		rec := &recordingSink{}
		progress.Emit(rec, u)
		if len(rec.got) != 1 || rec.got[0] != u {
			t.Errorf("Emit to non-nil sink delivered %+v, want exactly %+v", rec.got, u)
		}
	})
}
