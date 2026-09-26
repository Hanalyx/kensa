package engine

import (
	"fmt"
	"sort"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// RecoveryFindingCode names why recovery could not establish which handler
// restores which step of an interrupted transaction.
type RecoveryFindingCode string

// The identity findings. Each one means recovery refuses the whole entry
// before any restoration is dispatched.
const (
	// FindingPreStatesUnloadable: the pre-state bundle could not be read.
	FindingPreStatesUnloadable RecoveryFindingCode = "prestates_unloadable"
	// FindingDuplicateIntentIndex: the journal's intent names one step index twice.
	FindingDuplicateIntentIndex RecoveryFindingCode = "duplicate_intent_index"
	// FindingDuplicatePreStateIndex: the bundle holds two pre-states for one index.
	FindingDuplicatePreStateIndex RecoveryFindingCode = "duplicate_prestate_index"
	// FindingUnmatchedPreState: a pre-state has no intent step with its index.
	FindingUnmatchedPreState RecoveryFindingCode = "unmatched_prestate"
	// FindingMissingPreState: an intent step has no pre-state.
	FindingMissingPreState RecoveryFindingCode = "missing_prestate"
	// FindingMechanismMismatch: a pre-state's mechanism differs from its intent step's.
	FindingMechanismMismatch RecoveryFindingCode = "mechanism_mismatch"
	// FindingUnknownMechanism: the running binary registers no handler for the mechanism.
	FindingUnknownMechanism RecoveryFindingCode = "unknown_mechanism"
	// FindingCapturabilityDisagreement: the pre-state's Capturable flag
	// differs from what the registered handler reports.
	FindingCapturabilityDisagreement RecoveryFindingCode = "capturability_disagreement"
)

// RecoveryFinding is one reason an entry was refused. StepIndex is -1 for a
// finding about the whole bundle.
type RecoveryFinding struct {
	Code      RecoveryFindingCode
	StepIndex int
	Mechanism string
	Detail    string
}

// RecoveryRefusal is an open journal entry that recovery declined to
// compensate. Nothing was dispatched for it, no terminal record was written,
// and its journal entry and pre-states are left intact.
type RecoveryRefusal struct {
	TransactionID uuid.UUID
	HostID        string
	RuleID        string
	Findings      []RecoveryFinding
}

// RecoveryReport is everything one recovery run did: the transactions it
// compensated, and the ones it refused.
type RecoveryReport struct {
	Results  []*api.TransactionResult
	Refusals []RecoveryRefusal
}

// validateRecoveryIdentity decides whether recovery can establish, one to
// one, which handler restores which step. It returns every finding; an
// empty result means the bundle may be dispatched.
//
// It uses the controller's own registry, never the agent-mode lookup:
// in agent mode that lookup reports an unregistered mechanism as present
// and capturable, which is exactly the assumption this check exists to
// refuse. The agent is the same binary, so a mechanism unknown here is
// unknown there too.
//
// The journal and its pre-states were written in one atomic commit. That
// establishes all-or-nothing persistence. It does not establish that the
// writer was correct, or that the registry matches the version that wrote
// them, so a disagreement is refused rather than explained.
func (e *Engine) validateRecoveryIdentity(intent []api.Step, preStates []api.PreState) []RecoveryFinding {
	var findings []RecoveryFinding

	intentCount := map[int]int{}
	intentByIndex := map[int]api.Step{}
	for _, s := range intent {
		intentCount[s.Index]++
		intentByIndex[s.Index] = s
	}
	preCount := map[int]int{}
	preByIndex := map[int]api.PreState{}
	for _, p := range preStates {
		preCount[p.StepIndex]++
		preByIndex[p.StepIndex] = p
	}

	for idx, n := range intentCount {
		if n > 1 {
			findings = append(findings, RecoveryFinding{Code: FindingDuplicateIntentIndex, StepIndex: idx,
				Detail: fmt.Sprintf("the journal's intent names step %d %d times", idx, n)})
		}
	}
	for idx, n := range preCount {
		if n > 1 {
			findings = append(findings, RecoveryFinding{Code: FindingDuplicatePreStateIndex, StepIndex: idx,
				Mechanism: preByIndex[idx].Mechanism,
				Detail:    fmt.Sprintf("the bundle holds %d pre-states for step %d", n, idx)})
		}
	}
	for idx, p := range preByIndex {
		if intentCount[idx] == 0 {
			findings = append(findings, RecoveryFinding{Code: FindingUnmatchedPreState, StepIndex: idx,
				Mechanism: p.Mechanism, Detail: "no intent step has this index"})
		}
	}
	for idx, s := range intentByIndex {
		if preCount[idx] == 0 {
			findings = append(findings, RecoveryFinding{Code: FindingMissingPreState, StepIndex: idx,
				Mechanism: s.Mechanism, Detail: "no pre-state was recorded for this step"})
		}
	}

	// Pairs that are unique on both sides get the per-step checks.
	for idx, s := range intentByIndex {
		if intentCount[idx] != 1 || preCount[idx] != 1 {
			continue
		}
		p := preByIndex[idx]
		if p.Mechanism != s.Mechanism {
			findings = append(findings, RecoveryFinding{Code: FindingMechanismMismatch, StepIndex: idx,
				Mechanism: p.Mechanism,
				Detail:    fmt.Sprintf("pre-state mechanism %q, intent mechanism %q", p.Mechanism, s.Mechanism)})
		}
		for _, mech := range uniqueMechanisms(s.Mechanism, p.Mechanism) {
			h, ok := e.registry.Get(mech)
			if !ok {
				findings = append(findings, RecoveryFinding{Code: FindingUnknownMechanism, StepIndex: idx,
					Mechanism: mech, Detail: "no handler is registered for this mechanism"})
				continue
			}
			if mech == p.Mechanism && h.Capturable() != p.Capturable {
				findings = append(findings, RecoveryFinding{Code: FindingCapturabilityDisagreement, StepIndex: idx,
					Mechanism: mech,
					Detail:    fmt.Sprintf("pre-state records capturable=%v, handler reports %v", p.Capturable, h.Capturable())})
			}
		}
	}

	sortFindings(findings)
	return findings
}

func uniqueMechanisms(a, b string) []string {
	if a == b {
		return []string{a}
	}
	return []string{a, b}
}

// findingOrder fixes the report order so a refusal reads the same on every
// run: bundle-wide findings first, then by step, then by code.
var findingOrder = map[RecoveryFindingCode]int{
	FindingPreStatesUnloadable:       0,
	FindingDuplicateIntentIndex:      1,
	FindingDuplicatePreStateIndex:    2,
	FindingUnmatchedPreState:         3,
	FindingMissingPreState:           4,
	FindingMechanismMismatch:         5,
	FindingUnknownMechanism:          6,
	FindingCapturabilityDisagreement: 7,
}

func sortFindings(f []RecoveryFinding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].StepIndex != f[j].StepIndex {
			return f[i].StepIndex < f[j].StepIndex
		}
		if findingOrder[f[i].Code] != findingOrder[f[j].Code] {
			return findingOrder[f[i].Code] < findingOrder[f[j].Code]
		}
		return f[i].Mechanism < f[j].Mechanism
	})
}
