// Bridge between api/ Go types (api.StepResult, api.PreState,
// api.RollbackResult, api.Params) and their wire-level mirrors
// (WireStepResult, WirePreState, WireRollbackResult, plus
// structpb.Struct for Params). L-009 deliverable per spec
// agent-wire-handler-schema C-03 / C-04.
//
// **Why mirror types instead of using api/ types directly on the
// wire?**
//   - The api/ surface is the v1 public contract (OpenWatch
//     imports it). Tying the wire schema to it would make every
//     api/ change a wire-protocol change.
//   - api/ types use Go-native shapes (map[string]any, time.Time,
//     plain ints) that don't map cleanly to protobuf. Mirrors
//     give us a wire-friendly representation that the bridge
//     converts at the boundary.
//
// **Round-trip contract.** For the field domains the api/ types
// define, APIxxxToWire(WirexxxToAPI(v)) == v under
// reflect.DeepEqual, MODULO the L-007 numeric/time-widening
// caveats below.
//
// **Two time-encoding paths (important: don't confuse them).**
//   - Top-level time.Time fields — `PreState.CapturedAt`,
//     `RollbackResult.ExecutedAt` — use google.protobuf.Timestamp
//     and round-trip EXACTLY (nanosecond-preserving, no
//     widening). Bridge validates the Timestamp before
//     AsTime() to refuse out-of-range Seconds (year 292277 etc.).
//   - time.Time values NESTED inside `PreState.Data` go through
//     MapToStruct/StructToMap and widen to RFC3339Nano strings
//     (structpb.Struct has no native time type). Handler code
//     reading these back must use wirev1.DecodeTime or
//     time.Parse(time.RFC3339Nano, ...).
//
// **Numeric widening (PreState.Data only).** Integers in Data
// widen to int64 across the wire. Integers > 2^53 magnitude are
// REJECTED at encode time by MapToStruct. Top-level integer
// fields on the mirror types (WireStepResult.StepIndex etc.)
// use int32 explicitly and round-trip exactly within int32 range.
//
// **Handler-error dispatch convention.** api/ handlers return
// `(result, error)`. The L-011 dispatcher MUST translate:
//   - (result, nil)       → typed Response (ApplyResponse,
//                           CaptureResponse, RollbackResponse)
//   - (nil, err)          → Response with envelope-level Error
//                           field set (code + detail), no
//                           typed payload variant. The
//                           envelope Error is the channel for
//                           "handler couldn't run."
//   - (failed result, nil) → typed Response carrying the result
//                           with Success=false + Detail set
//                           (i.e., "handler ran but the action
//                           failed"). This is distinct from
//                           "handler couldn't run."
// Apply / Capture / Rollback all follow this same pattern.
//
// **Asymmetric error returns on bridge functions.**
// APIStepResultToWire / APIRollbackResultToWire have no failure
// modes (all fields are primitives + time.Time). APIPreStateToWire
// CAN fail because Data goes through MapToStruct which rejects
// unsupported types and oversized integers. WirePreStateToAPI
// and WireRollbackResultToAPI return errors because Timestamp
// validation can fail. L-011 dispatcher authors: handle errors
// explicitly; do NOT write a generic must-wire wrapper.

package wirev1

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Hanalyx/kensa-go/api"
)

// APIStepResultToWire converts api.StepResult → WireStepResult.
// Total — no failure modes; all api fields map to wire fields
// without lossy conversions.
func APIStepResultToWire(r api.StepResult) *WireStepResult {
	return &WireStepResult{
		StepIndex:  int32(r.StepIndex),
		Mechanism:  r.Mechanism,
		Capturable: r.Capturable,
		Success:    r.Success,
		Detail:     r.Detail,
		Stranded:   r.Stranded,
	}
}

// WireStepResultToAPI converts WireStepResult → api.StepResult.
// A nil input returns a zero-value api.StepResult so handlers
// don't have to nil-check every field.
func WireStepResultToAPI(w *WireStepResult) api.StepResult {
	if w == nil {
		return api.StepResult{}
	}
	return api.StepResult{
		StepIndex:  int(w.GetStepIndex()),
		Mechanism:  w.GetMechanism(),
		Capturable: w.GetCapturable(),
		Success:    w.GetSuccess(),
		Detail:     w.GetDetail(),
		Stranded:   w.GetStranded(),
	}
}

// APIPreStateToWire converts api.PreState → WirePreState. The
// Data map[string]any goes through MapToStruct, applying the
// L-007 numeric/time-widening + 2^53 + max-nesting contracts.
// CapturedAt becomes a protobuf Timestamp (exact, unlike the
// MapToStruct RFC3339-string path for embedded time.Time in
// Data).
func APIPreStateToWire(p api.PreState) (*WirePreState, error) {
	data, err := MapToStruct(p.Data)
	if err != nil {
		return nil, fmt.Errorf("APIPreStateToWire: encode Data: %w", err)
	}
	return &WirePreState{
		StepIndex:  int32(p.StepIndex),
		Mechanism:  p.Mechanism,
		Capturable: p.Capturable,
		Data:       data,
		CapturedAt: timestamppb.New(p.CapturedAt),
	}, nil
}

// WirePreStateToAPI converts WirePreState → api.PreState.
// Validates the Timestamp before AsTime() to refuse out-of-
// range Seconds values that would otherwise produce silently-
// corrupt time.Time (e.g., year 292277 from MaxInt64 Seconds —
// such a value would land in the signed audit trail).
func WirePreStateToAPI(w *WirePreState) (api.PreState, error) {
	if w == nil {
		return api.PreState{}, nil
	}
	data, err := StructToMap(w.GetData())
	if err != nil {
		return api.PreState{}, fmt.Errorf("WirePreStateToAPI: decode Data: %w", err)
	}
	capturedAt, err := safeTimestampToTime(w.GetCapturedAt(), "PreState.CapturedAt")
	if err != nil {
		return api.PreState{}, fmt.Errorf("WirePreStateToAPI: %w", err)
	}
	return api.PreState{
		StepIndex:  int(w.GetStepIndex()),
		Mechanism:  w.GetMechanism(),
		Capturable: w.GetCapturable(),
		Data:       data,
		CapturedAt: capturedAt,
	}, nil
}

// APIRollbackResultToWire converts api.RollbackResult →
// WireRollbackResult. Total — no failure modes.
func APIRollbackResultToWire(r api.RollbackResult) *WireRollbackResult {
	return &WireRollbackResult{
		StepIndex:      int32(r.StepIndex),
		Mechanism:      r.Mechanism,
		Success:        r.Success,
		Detail:         r.Detail,
		PartialRestore: r.PartialRestore,
		Source:         r.Source,
		ExecutedAt:     timestamppb.New(r.ExecutedAt),
	}
}

// WireRollbackResultToAPI converts WireRollbackResult →
// api.RollbackResult. Validates the Timestamp before
// AsTime() — same out-of-range protection as
// WirePreStateToAPI.
//
// Returns an error for a malformed Timestamp; nil input returns
// a zero RollbackResult with nil error.
func WireRollbackResultToAPI(w *WireRollbackResult) (api.RollbackResult, error) {
	if w == nil {
		return api.RollbackResult{}, nil
	}
	executedAt, err := safeTimestampToTime(w.GetExecutedAt(), "RollbackResult.ExecutedAt")
	if err != nil {
		return api.RollbackResult{}, fmt.Errorf("WireRollbackResultToAPI: %w", err)
	}
	return api.RollbackResult{
		StepIndex:      int(w.GetStepIndex()),
		Mechanism:      w.GetMechanism(),
		Success:        w.GetSuccess(),
		Detail:         w.GetDetail(),
		PartialRestore: w.GetPartialRestore(),
		Source:         w.GetSource(),
		ExecutedAt:     executedAt,
	}, nil
}

// APIParamsToWire converts api.Params → *structpb.Struct via
// MapToStruct. Same widening + 2^53 + max-nesting contracts as
// PreState.Data. Returns an error for unsupported value types
// or oversized integers.
//
// Symmetric with APIPreStateToWire's handling of PreState.Data —
// L-011's dispatcher author builds Apply / Capture requests by
// calling this helper instead of converting api.Params to
// map[string]any and calling MapToStruct manually.
func APIParamsToWire(p api.Params) (*structpb.Struct, error) {
	if p == nil {
		return MapToStruct(nil)
	}
	return MapToStruct(map[string]any(p))
}

// WireParamsToAPI converts *structpb.Struct → api.Params. The
// numeric-widening contract from L-007 applies: integers in
// the Struct come back as int64, time.Time values nested in
// the Struct come back as RFC3339Nano strings.
func WireParamsToAPI(s *structpb.Struct) (api.Params, error) {
	m, err := StructToMap(s)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, nil
	}
	return api.Params(m), nil
}

// safeTimestampToTime validates a protobuf Timestamp before
// calling AsTime(). Without CheckValid, a peer-sent
// Timestamp{Seconds: MaxInt64} silently produces a time.Time
// in year 292277 — a value that would land in the signed
// audit trail and confuse deadman-window arithmetic. CheckValid
// enforces the documented [0001-01-01, 9999-12-31] range.
//
// The fieldName argument is the field's path for diagnostic-
// friendly errors (e.g., "PreState.CapturedAt").
func safeTimestampToTime(ts *timestamppb.Timestamp, fieldName string) (time.Time, error) {
	// timestamppb.Timestamp.CheckValid returns nil for the
	// nil-pointer case (zero value semantics); AsTime() on a
	// nil receiver returns the zero time.Time. This is the
	// "no timestamp set" case which we want to allow.
	if ts == nil {
		return time.Time{}, nil
	}
	if err := ts.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("invalid %s timestamp: %w", fieldName, err)
	}
	return ts.AsTime(), nil
}
