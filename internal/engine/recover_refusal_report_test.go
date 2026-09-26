package engine_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/store"
)

// The refusal report is new: before it existed, a refused or skipped entry
// was simply absent from Recover's results. These tests have no baseline
// to fail against; each is shown to guard its finding by mutation.

type findingKey struct {
	code engine.RecoveryFindingCode
	step int
	mech string
}

func refusalFor(t *testing.T, rep *engine.RecoveryReport, id uuid.UUID) engine.RecoveryRefusal {
	t.Helper()
	for _, r := range rep.Refusals {
		if r.TransactionID == id {
			return r
		}
	}
	t.Fatalf("no refusal reported for %s", id)
	return engine.RecoveryRefusal{}
}

func keys(r engine.RecoveryRefusal) map[findingKey]bool {
	out := map[findingKey]bool{}
	for _, f := range r.Findings {
		out[findingKey{f.Code, f.StepIndex, f.Mechanism}] = true
	}
	return out
}

// @spec recovery-replay
// @ac AC-08
func TestRecoverRefusal_ReportsEveryFinding(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-08")
	cases := []struct {
		name   string
		intent []api.Step
		pre    []api.PreState
		want   []findingKey
	}{
		{"duplicate intent index", []api.Step{step(0, "cap_a"), step(0, "cap_b")},
			[]api.PreState{pre(0, "cap_a", true)},
			[]findingKey{{engine.FindingDuplicateIntentIndex, 0, ""}}},
		{"unmatched pre-state", []api.Step{step(0, "cap_a")},
			[]api.PreState{pre(0, "cap_a", true), pre(5, "cap_b", true)},
			[]findingKey{{engine.FindingUnmatchedPreState, 5, "cap_b"}}},
		{"missing pre-state", []api.Step{step(0, "cap_a"), step(1, "cap_b")},
			[]api.PreState{pre(0, "cap_a", true)},
			[]findingKey{{engine.FindingMissingPreState, 1, "cap_b"}}},
		{"mechanism mismatch", []api.Step{step(0, "cap_a")},
			[]api.PreState{pre(0, "cap_z", true)},
			[]findingKey{{engine.FindingMechanismMismatch, 0, "cap_z"}}},
		{"unknown mechanism", []api.Step{step(0, "ghost")},
			[]api.PreState{pre(0, "ghost", true)},
			[]findingKey{{engine.FindingUnknownMechanism, 0, "ghost"}}},
		{"unknown marker", []api.Step{step(0, "ghost_marker")},
			[]api.PreState{pre(0, "ghost_marker", false)},
			[]findingKey{{engine.FindingUnknownMechanism, 0, "ghost_marker"}}},
		{"capturability disagreement", []api.Step{step(0, "cap_a")},
			[]api.PreState{pre(0, "cap_a", false)},
			[]findingKey{{engine.FindingCapturabilityDisagreement, 0, "cap_a"}}},
		{"several at once", []api.Step{step(0, "cap_a"), step(1, "cap_b"), step(2, "ghost")},
			[]api.PreState{pre(0, "cap_z", true), pre(2, "ghost", true), pre(7, "cap_c", true)},
			[]findingKey{
				{engine.FindingMechanismMismatch, 0, "cap_z"},
				{engine.FindingMissingPreState, 1, "cap_b"},
				{engine.FindingUnknownMechanism, 2, "ghost"},
				{engine.FindingUnmatchedPreState, 7, "cap_c"},
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newIdentityRig(t)
			id := rig.crash("h", tc.intent, tc.pre)
			rep, err := rig.engine().RecoverReport(context.Background(), engine.NewFakeTransport(), "h")
			if err != nil {
				t.Fatalf("RecoverReport: %v", err)
			}
			got := keys(refusalFor(t, rep, id))
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("finding %+v missing; got %v", w, got)
				}
			}
			if len(got) != len(tc.want) {
				t.Errorf("got %d findings, want %d: %v", len(got), len(tc.want), got)
			}
		})
	}
}

// @spec recovery-replay
// @ac AC-08
func TestRecoverRefusal_DuplicatePreStateReported(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-08")
	js := newJournalRecorderStore()
	rig := newIdentityRig(t)
	id := uuid.New()
	entry := api.JournalEntry{TxnID: id, HostID: "h", RuleID: "r", Intent: []api.Step{step(0, "cap_a")}}
	if err := js.PrepareTransaction(context.Background(), entry,
		[]api.PreState{pre(0, "cap_a", true), pre(0, "cap_a", true)}); err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.WithRegistry(rig.reg), engine.WithStore(js))
	rep, err := e.RecoverReport(context.Background(), engine.NewFakeTransport(), "h")
	if err != nil {
		t.Fatal(err)
	}
	if !keys(refusalFor(t, rep, id))[findingKey{engine.FindingDuplicatePreStateIndex, 0, "cap_a"}] {
		t.Error("duplicate pre-state index not reported")
	}
}

// failingPreStateStore is an isolated SQLite store whose pre-state read
// fails, to exercise the unreadable-bundle path.
type failingPreStateStore struct{ *store.SQLite }

func (failingPreStateStore) LoadPreStates(context.Context, uuid.UUID) ([]api.PreState, error) {
	return nil, errors.New("induced pre-state read failure")
}

// @spec recovery-replay
// @ac AC-08
func TestRecoverRefusal_UnreadableBundle(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-08")
	rig := newIdentityRig(t)
	id := rig.crash("h", []api.Step{step(0, "cap_a")}, []api.PreState{pre(0, "cap_a", true)})
	e := engine.New(engine.WithRegistry(rig.reg), engine.WithStore(failingPreStateStore{rig.st}))
	rep, err := e.RecoverReport(context.Background(), engine.NewFakeTransport(), "h")
	if err != nil {
		t.Fatal(err)
	}
	if !keys(refusalFor(t, rep, id))[findingKey{engine.FindingPreStatesUnloadable, -1, ""}] {
		t.Error("unreadable bundle not reported")
	}
	if !rig.isOpen(id) || rig.hasTerminal(id) || len(rig.log.snapshot()) != 0 {
		t.Error("an unreadable bundle was not left open and untouched")
	}
}

// @spec recovery-replay
// @ac AC-08
func TestRecoverRefusal_NoFindingBecomesARollbackRow(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-08")
	// A validation refusal is not a reversal attempt, so it must never be
	// recorded as one.
	rig := newIdentityRig(t)
	rig.crash("h", []api.Step{step(0, "cap_a")}, []api.PreState{pre(0, "cap_z", true)})
	good := rig.crash("h", []api.Step{step(0, "cap_b")}, []api.PreState{pre(0, "cap_b", true)})
	rep, err := rig.engine().RecoverReport(context.Background(), engine.NewFakeTransport(), "h")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].TransactionID != good {
		t.Fatalf("results = %d, want only the valid entry", len(rep.Results))
	}
	for _, rr := range rep.Results[0].RollbackResults {
		if rr.Mechanism != "cap_b" {
			t.Errorf("a rollback row names %q, which was never dispatched", rr.Mechanism)
		}
	}
}

// @spec recovery-replay
// @ac AC-08
func TestRecoverRefusal_RecoverReturnsRefusedError(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-08")
	// A caller of the older Recover signature still learns the run was
	// incomplete, and still receives the entries that were compensated.
	rig := newIdentityRig(t)
	rig.crash("h", []api.Step{step(0, "cap_a")}, []api.PreState{pre(0, "cap_z", true)})
	good := rig.crash("h", []api.Step{step(0, "cap_b")}, []api.PreState{pre(0, "cap_b", true)})
	res, err := rig.engine().Recover(context.Background(), engine.NewFakeTransport(), "h")
	var refused *engine.RecoveryRefusedError
	if !errors.As(err, &refused) || len(refused.Refusals) != 1 {
		t.Fatalf("err = %v, want a RecoveryRefusedError with one refusal", err)
	}
	if len(res) != 1 || res[0].TransactionID != good {
		t.Error("the compensated entry's result was not returned with the error")
	}
}

// @spec recovery-replay
// @ac AC-08
func TestRecoverRefusal_IndependentFindingsOnAmbiguousRecords(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-08")
	// A record that cannot be paired still carries facts of its own. They
	// are reported, in a fixed order, and no pair comparison is attempted
	// where the pairing is ambiguous.
	cases := []struct {
		name   string
		intent []api.Step
		pre    []api.PreState
		want   []findingKey
	}{
		{"one unregistered mechanism named by both sides is reported once",
			[]api.Step{step(0, "ghost")},
			[]api.PreState{pre(0, "ghost", true)},
			[]findingKey{
				{engine.FindingUnknownMechanism, 0, "ghost"},
			}},
		{"unmatched pre-state with an unregistered mechanism",
			[]api.Step{step(0, "cap_a")},
			[]api.PreState{pre(0, "cap_a", true), pre(5, "ghost", true)},
			[]findingKey{
				{engine.FindingUnmatchedPreState, 5, "ghost"},
				{engine.FindingUnknownMechanism, 5, "ghost"},
			}},
		{"missing pre-state for an unregistered intent step",
			[]api.Step{step(0, "cap_a"), step(1, "ghost")},
			[]api.PreState{pre(0, "cap_a", true)},
			[]findingKey{
				{engine.FindingMissingPreState, 1, "ghost"},
				{engine.FindingUnknownMechanism, 1, "ghost"},
			}},
		{"duplicate intent index, both intent mechanisms checked",
			[]api.Step{step(0, "cap_a"), step(0, "ghost")},
			[]api.PreState{pre(0, "cap_a", false)},
			[]findingKey{
				{engine.FindingDuplicateIntentIndex, 0, ""},
				{engine.FindingUnknownMechanism, 0, "ghost"},
				{engine.FindingCapturabilityDisagreement, 0, "cap_a"},
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newIdentityRig(t)
			id := rig.crash("h", tc.intent, tc.pre)
			rep, err := rig.engine().RecoverReport(context.Background(), engine.NewFakeTransport(), "h")
			if err != nil {
				t.Fatalf("RecoverReport: %v", err)
			}
			var got []findingKey
			for _, f := range refusalFor(t, rep, id).Findings {
				got = append(got, findingKey{f.Code, f.StepIndex, f.Mechanism})
			}
			// Exact order: step first, then code, then mechanism.
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("findings =\n %v\nwant\n %v", got, tc.want)
			}
		})
	}
}

// @spec recovery-replay
// @ac AC-08
func TestRecoverRefusal_DuplicatePreStatesCheckedIndividually(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-08")
	js := newJournalRecorderStore()
	rig := newIdentityRig(t)
	id := uuid.New()
	entry := api.JournalEntry{TxnID: id, HostID: "h", RuleID: "r", Intent: []api.Step{step(0, "cap_a")}}
	if err := js.PrepareTransaction(context.Background(), entry,
		[]api.PreState{pre(0, "cap_a", true), pre(0, "noncap_n", true)}); err != nil {
		t.Fatal(err)
	}
	rep, err := engine.New(engine.WithRegistry(rig.reg), engine.WithStore(js)).
		RecoverReport(context.Background(), engine.NewFakeTransport(), "h")
	if err != nil {
		t.Fatal(err)
	}
	got := keys(refusalFor(t, rep, id))
	for _, w := range []findingKey{
		{engine.FindingDuplicatePreStateIndex, 0, "noncap_n"},
		{engine.FindingCapturabilityDisagreement, 0, "noncap_n"},
	} {
		if !got[w] {
			t.Errorf("finding %+v missing; got %v", w, got)
		}
	}
	if got[findingKey{engine.FindingMechanismMismatch, 0, "noncap_n"}] || got[findingKey{engine.FindingMechanismMismatch, 0, "cap_a"}] {
		t.Error("a pair comparison was made across an ambiguous index")
	}
}
