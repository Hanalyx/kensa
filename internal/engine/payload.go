package engine

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Hanalyx/kensa/api"
)

// The evidence envelope must own every byte the signature covers.
//
// Before this layer existed, the envelope shared its backing arrays with
// the [api.TransactionResult] handed back to the caller, so a later write
// through the result (marking a step stranded) silently rewrote signed
// content and invalidated the signature on both the returned and the
// persisted envelope. Copying at envelope-construction time removes the
// aliasing rather than relying on nobody writing through the result again.
//
// Only [api.PreState] needs a recursive copy. StepResult, RollbackResult,
// ValidatorResult and FrameworkRef hold scalars (plus an immutable
// time.Time), so copying the slice copies the values.

// copyStringKeyedMap deep-copies a captured-state map. A non-nil error
// names the first value whose Go type this layer cannot copy safely.
func copyStringKeyedMap(in map[string]any, path string) (map[string]any, error) {
	if in == nil {
		return nil, nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		cv, err := copyDataValue(v, path+"."+k)
		if err != nil {
			return nil, err
		}
		out[k] = cv
	}
	return out, nil
}

// copyDataValue copies one captured-state value.
//
// The supported set is the set the corpus actually produces, established
// by inventorying every PreState.Data producer: handler literals (string,
// bool, nested map[string]any, []any, []string), and the two decode-side
// producers — the SQLite reload and the agent wire format — which both
// normalize through JSON/protobuf shapes (float64, []any, map[string]any).
//
// Anything outside that set fails closed. Retaining the original value
// would re-introduce the alias this layer exists to remove, and doing so
// silently is how the defect shipped in the first place.
func copyDataValue(v any, path string) (any, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case bool, string, json.Number,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		// Scalars copy by value. Integer kinds are listed explicitly so
		// width and precision survive: a JSON round-trip would widen them
		// to float64 and lose exactness above 2^53.
		return t, nil
	case []string:
		// A typed nil stays nil: turning it into an empty slice would
		// change the captured state's JSON from null to [].
		if t == nil {
			return t, nil
		}
		out := make([]string, len(t))
		copy(out, t)
		return out, nil
	case []any:
		if t == nil {
			return t, nil
		}
		out := make([]any, len(t))
		for i := range t {
			cv, err := copyDataValue(t[i], path+"["+strconv.Itoa(i)+"]")
			if err != nil {
				return nil, err
			}
			out[i] = cv
		}
		return out, nil
	case map[string]any:
		return copyStringKeyedMap(t, path)
	default:
		return nil, fmt.Errorf("captured state at %s has unsupported type %T", path, v)
	}
}

// copyPreStates deep-copies a captured-state bundle for the envelope.
//
// An entry whose Data cannot be copied keeps its identifying fields and
// gets a diagnostic map in place of the state: the record still shows
// which step produced unrepresentable state and why, and the original map
// stays unreachable from the envelope. Entries that copy cleanly are
// unaffected, so one bad value does not erase the rest of the evidence.
// The returned error is non-nil whenever any substitution happened; the
// caller demotes the transaction on it.
func copyPreStates(in []api.PreState) ([]api.PreState, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]api.PreState, len(in))
	var firstErr error
	for i, ps := range in {
		out[i] = ps
		data, err := copyStringKeyedMap(ps.Data, "data")
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			out[i].Data = unrepresentableData(ps, err)
			continue
		}
		out[i].Data = data
	}
	return out, firstErr
}

// unrepresentableData is the string-only stand-in recorded for a
// captured-state map this layer cannot copy. Every value is a string, so
// the stand-in itself is always representable.
func unrepresentableData(ps api.PreState, err error) map[string]any {
	return map[string]any{
		"kensa_state_unrepresentable": "true",
		"mechanism":                   ps.Mechanism,
		"step_index":                  strconv.Itoa(ps.StepIndex),
		"reason":                      err.Error(),
	}
}

// copySteps, copyRollbacks, copyValidators and copyFrameworkRefs give the
// envelope its own array. The element types hold no reference fields, so
// a slice copy is a full copy — asserted by TestPayloadCopy_ElementTypes.
func copySteps(in []api.StepResult) []api.StepResult {
	if in == nil {
		return nil
	}
	out := make([]api.StepResult, len(in))
	copy(out, in)
	return out
}

func copyRollbacks(in []api.RollbackResult) []api.RollbackResult {
	if in == nil {
		return nil
	}
	out := make([]api.RollbackResult, len(in))
	copy(out, in)
	return out
}

func copyValidators(in []api.ValidatorResult) []api.ValidatorResult {
	if in == nil {
		return nil
	}
	out := make([]api.ValidatorResult, len(in))
	copy(out, in)
	return out
}

func copyFrameworkRefs(in []api.FrameworkRef) []api.FrameworkRef {
	if in == nil {
		return nil
	}
	out := make([]api.FrameworkRef, len(in))
	copy(out, in)
	return out
}
