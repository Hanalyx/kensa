package diff

import (
	"testing"

	"github.com/Hanalyx/kensa-go/internal/store"
)

func mkTxn(rule, status string) store.SessionTxn {
	return store.SessionTxn{RuleID: rule, Status: status}
}

func TestComputeSessionDiff_AllSections(t *testing.T) {
	from := []store.SessionTxn{
		mkTxn("rule-removed", "committed"),
		mkTxn("rule-changed", "committed"),
		mkTxn("rule-unchanged", "committed"),
	}
	to := []store.SessionTxn{
		mkTxn("rule-added", "rolled_back"),
		mkTxn("rule-changed", "rolled_back"),
		mkTxn("rule-unchanged", "committed"),
	}

	added, removed, changed, unchanged := ComputeSessionDiff(from, to)

	if len(added) != 1 || added[0].RuleID != "rule-added" {
		t.Errorf("added: got %+v", added)
	}
	if added[0].FromStatus != "" || added[0].ToStatus != "rolled_back" {
		t.Errorf("added shape: %+v", added[0])
	}
	if len(removed) != 1 || removed[0].RuleID != "rule-removed" {
		t.Errorf("removed: got %+v", removed)
	}
	if removed[0].FromStatus != "committed" || removed[0].ToStatus != "" {
		t.Errorf("removed shape: %+v", removed[0])
	}
	if len(changed) != 1 || changed[0].RuleID != "rule-changed" {
		t.Errorf("changed: got %+v", changed)
	}
	if changed[0].FromStatus != "committed" || changed[0].ToStatus != "rolled_back" {
		t.Errorf("changed shape: %+v", changed[0])
	}
	if len(unchanged) != 1 || unchanged[0].RuleID != "rule-unchanged" {
		t.Errorf("unchanged: got %+v", unchanged)
	}
}

func TestComputeSessionDiff_Empty(t *testing.T) {
	added, removed, changed, unchanged := ComputeSessionDiff(nil, nil)
	if len(added) != 0 || len(removed) != 0 || len(changed) != 0 || len(unchanged) != 0 {
		t.Errorf("empty input should yield empty slices")
	}
}

func TestComputeSessionDiff_OnlyAdded(t *testing.T) {
	to := []store.SessionTxn{
		mkTxn("a", "committed"),
		mkTxn("b", "rolled_back"),
	}
	added, removed, changed, _ := ComputeSessionDiff(nil, to)
	if len(added) != 2 || len(removed) != 0 || len(changed) != 0 {
		t.Errorf("expected only added; got added=%d removed=%d changed=%d",
			len(added), len(removed), len(changed))
	}
}

func TestComputeSessionDiff_OnlyRemoved(t *testing.T) {
	from := []store.SessionTxn{
		mkTxn("a", "committed"),
		mkTxn("b", "rolled_back"),
	}
	added, removed, changed, _ := ComputeSessionDiff(from, nil)
	if len(removed) != 2 || len(added) != 0 || len(changed) != 0 {
		t.Errorf("expected only removed; got %d", len(removed))
	}
}

// TestComputeSessionDiff_DedupesRetries locks AC-07: multiple
// transactions for the same rule within one input slice
// dedup to the LAST entry (chronologically latest, since the
// store query orders ASC by started_at).
func TestComputeSessionDiff_DedupesRetries(t *testing.T) {
	from := []store.SessionTxn{
		mkTxn("rule-x", "errored"),     // earlier attempt
		mkTxn("rule-x", "rolled_back"), // retry
		mkTxn("rule-x", "committed"),   // final success
	}
	to := []store.SessionTxn{
		mkTxn("rule-x", "committed"),
	}
	_, _, changed, unchanged := ComputeSessionDiff(from, to)
	if len(changed) != 0 {
		t.Errorf("rule-x's last-attempt status (committed) matches to-side; expected unchanged: got changed=%v", changed)
	}
	if len(unchanged) != 1 {
		t.Errorf("expected unchanged=1; got %v", unchanged)
	}
}

func TestComputeSessionDiff_Deterministic(t *testing.T) {
	from := []store.SessionTxn{
		mkTxn("z-rule", "committed"),
		mkTxn("a-rule", "committed"),
		mkTxn("m-rule", "committed"),
	}
	to := []store.SessionTxn{
		mkTxn("z-rule", "rolled_back"),
		mkTxn("a-rule", "rolled_back"),
		mkTxn("m-rule", "rolled_back"),
	}
	for i := 0; i < 3; i++ {
		_, _, changed, _ := ComputeSessionDiff(from, to)
		want := []string{"a-rule", "m-rule", "z-rule"}
		if len(changed) != 3 {
			t.Fatalf("iter %d: expected 3 changed; got %d", i, len(changed))
		}
		for j, want := range want {
			if changed[j].RuleID != want {
				t.Errorf("iter %d: changed[%d]: got %q want %q", i, j, changed[j].RuleID, want)
			}
		}
	}
}

func TestComputeSessionDiff_StatusEqualityIsExact(t *testing.T) {
	// "committed" vs "Committed" must NOT match — diff is
	// raw status comparison, not normalized. The store
	// always writes lowercase per api.TransactionStatus
	// convention, so casing differences here would be a
	// signal of corrupted data the operator should see.
	from := []store.SessionTxn{mkTxn("r1", "committed")}
	to := []store.SessionTxn{mkTxn("r1", "Committed")}
	_, _, changed, _ := ComputeSessionDiff(from, to)
	if len(changed) != 1 {
		t.Errorf("case-sensitive status compare: expected changed=1; got %v", changed)
	}
}
