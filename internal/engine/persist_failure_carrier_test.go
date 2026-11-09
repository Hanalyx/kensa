package engine_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
)

// These cases state the persistence-failure contract for every terminal
// status, before the change that makes it hold. A terminal record that fails
// to save must say so on the result, whatever the status. Today the failure
// reaches the caller only for the statuses that demote to Errored and for
// Errored itself; partially_applied, rollback_failed and recovered keep their
// status and drop it. The carrier is a result field, PersistenceError, which
// does not exist yet, so the cases read it through the result's JSON and do
// not name it in Go.
//
// @spec engine-transaction
// @ac AC-13 (extended to every status; the new criteria are not in the spec yet)

// persistenceCarrier reports whether res carries a persistence failure in a
// PersistenceError field: present in the JSON and not empty.
func persistenceCarrier(t *testing.T, res *api.TransactionResult) bool {
	t.Helper()
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	v, ok := m["PersistenceError"]
	if !ok {
		return false
	}
	s := strings.TrimSpace(string(v))
	return s != "" && s != "null" && s != `""` && s != "{}"
}

// errorNames reports whether res.Error mentions the induced persistence
// failure.
func errorNamesPersist(res *api.TransactionResult) bool {
	return res.Error != nil && strings.Contains(res.Error.Error(), "induced persist failure")
}

// persistFailJournalStore is a journal-capable store whose terminal write
// fails, so a recovered transaction meets the same failure as a live one.
type persistFailJournalStore struct {
	*journalRecorderStore
}

func (persistFailJournalStore) PersistResult(context.Context, *api.TransactionResult) error {
	return errors.New("induced persist failure")
}

func TestPersistFailure_EveryStatusCarriesTheFailure(t *testing.T) {
	demoted := func(t *testing.T, res *api.TransactionResult, from api.TransactionStatus) {
		t.Helper()
		if res.Status != api.StatusErrored {
			t.Fatalf("%s with a failed terminal write: got %s, want errored", from, res.Status)
		}
		if !errorNamesPersist(res) {
			t.Errorf("%s demoted to errored, but Error does not carry the persistence failure: %v", from, res.Error)
		}
	}
	kept := func(t *testing.T, res *api.TransactionResult, want api.TransactionStatus) {
		t.Helper()
		if res.Status != want {
			t.Fatalf("got %s, want %s (a host-state status keeps its status)", res.Status, want)
		}
		if !persistenceCarrier(t, res) && !errorNamesPersist(res) {
			t.Errorf("%s with a failed terminal write carries no persistence failure: "+
				"no PersistenceError field on the result and Error is %v", want, res.Error)
		}
	}

	t.Run("committed demotes to errored", func(t *testing.T) {
		res := runToStatus(t, persistFailStore{}, realSigner(t), capHandler(), true)
		demoted(t, res, api.StatusCommitted)
	})

	t.Run("rolled_back demotes to errored", func(t *testing.T) {
		res := runToStatus(t, persistFailStore{}, realSigner(t), capHandler(), true,
			engine.WithForceValidateFail())
		demoted(t, res, api.StatusRolledBack)
	})

	t.Run("staged demotes to errored", func(t *testing.T) {
		h := capHandler()
		h.ApplyResult = &api.StepResult{Success: true, Staged: true}
		res := runToStatus(t, persistFailStore{}, realSigner(t), h, true)
		demoted(t, res, api.StatusStaged)
	})

	t.Run("errored keeps both failures", func(t *testing.T) {
		res := runToStatus(t, persistFailStore{}, signFailSigner{}, capHandler(), true)
		if res.Status != api.StatusErrored {
			t.Fatalf("got %s, want errored", res.Status)
		}
		if res.Error == nil || !strings.Contains(res.Error.Error(), "induced signer failure") ||
			!errorNamesPersist(res) {
			t.Errorf("errored result must carry both the signer and the persistence failure; Error is %v", res.Error)
		}
	})

	t.Run("partially_applied keeps its status and carries the failure", func(t *testing.T) {
		res := runToStatus(t, persistFailStore{}, realSigner(t), noncapHandler(), false,
			engine.WithForceValidateFail())
		kept(t, res, api.StatusPartiallyApplied)
	})

	t.Run("rollback_failed keeps its status and carries the failure", func(t *testing.T) {
		h := capHandler()
		h.RollbackResult = &api.RollbackResult{Success: false, Detail: "induced rollback failure"}
		res := runToStatus(t, persistFailStore{}, realSigner(t), h, true, engine.WithForceValidateFail())
		kept(t, res, api.StatusRollbackFailed)
	})

	// TestPersistFailure_DemotionMatrix has no recovered case. Recovery
	// finalizes through the same terminal write, so it meets the same failure.
	t.Run("recovered keeps its status and carries the failure", func(t *testing.T) {
		js := persistFailJournalStore{newJournalRecorderStore()}
		h := &engine.FakeHandler{
			HandlerName:    "rec_persist",
			IsCapturable:   true,
			RollbackResult: &api.RollbackResult{Success: true, Detail: "restored"},
		}
		e := durabilityEngine(t, js, nil, h)
		prepareCrashedTxn(t, js.journalRecorderStore, "rec_persist", "host-p")
		results, err := e.Recover(context.Background(), engine.NewFakeTransport(), "host-p")
		if err != nil {
			t.Fatalf("Recover: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 recovered transaction, got %d", len(results))
		}
		kept(t, results[0], api.StatusRecovered)
	})

	t.Run("a saved record carries no persistence failure", func(t *testing.T) {
		res := runToStatus(t, nil, realSigner(t), capHandler(), true)
		if res.Status != api.StatusCommitted {
			t.Fatalf("got %s, want committed", res.Status)
		}
		if persistenceCarrier(t, res) {
			t.Error("a result whose record saved carries a persistence failure")
		}
	})
}
