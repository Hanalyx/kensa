// Bridge between Go-native map[string]interface{} (the shape of
// api.PreState.Data and api.Params) and protobuf's Struct/Value
// types (the wire-compatible heterogeneous-data container).
//
// Why this exists: kensa handler authors write Capture / Apply /
// Rollback against `map[string]any`. Putting protobuf-Value
// unwrapping into every handler would be repetitive and noisy.
// MapToStruct/StructToMap let the wire layer translate at the
// boundary so handler code stays native-Go.
//
// **Versioning policy.** This bridge is wirev1-scoped. A future
// wirev2 package ships its own bridge.go (parallel package per
// spec C-07). Don't import wirev1.MapToStruct from wirev2 code —
// the wire-format generation may diverge and the type aliasing
// would mask schema drift.
//
// **Numeric round-trip contract.**
//   - On encode, Go integers (int, int8..int64, uint, uint8..uint32)
//     are stored as float64 on the wire. uint64 / int64 values whose
//     absolute magnitude exceeds 2^53 are REJECTED at encode time
//     rather than silently losing precision (float64 has a 53-bit
//     mantissa; above 2^53, not every integer is representable).
//   - On decode, NumberValue is returned as int64 when the value
//     rounds to an integer within [-2^53, 2^53]; otherwise float64.
//   - All Go integer types thus widen to int64 across a round-trip.
//     Handlers that previously type-asserted `pre.Data["mode"].(int)`
//     break after agent round-trip; use `.(int64)` or the
//     api.PreState.Data documentation in api/transaction.go.
//
// **Time round-trip contract.**
//   - time.Time values are encoded as RFC3339Nano strings (matching
//     the JSON contract operators already see in evidence envelopes).
//   - On decode, the value comes back as `string`, not `time.Time`.
//     The asymmetry is unavoidable: protobuf's Struct has no native
//     time type, and string is a stable serialized form.
//   - Handlers that previously type-asserted `pre.Data["t"].(time.Time)`
//     break after agent round-trip. Use the DecodeTime helper or
//     a manual time.Parse(time.RFC3339Nano, ...).

package wirev1

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

// maxNestingDepth bounds recursive encode/decode so a malicious
// peer cannot DoS the agent with a deeply-nested Struct. The
// legitimate PreState shapes kensa produces are single-digit
// deep; 32 is generous while still well below the
// goroutine-stack-exhaustion threshold.
//
// Without this bound, a hostile controller (or man-in-the-middle on
// a compromised SSH session) could send a Request whose payload
// decodes to a 250K-deep structpb.Struct, blowing the agent's stack
// with `runtime: goroutine stack exceeds 1000000000-byte limit`.
// Agent runs with sudo escalation; crash = denied remediation =
// denied compliance enforcement.
const maxNestingDepth = 32

// maxSafeInteger is 2^53 — the largest integer for which every
// integer in [-N, N] is exactly representable as float64. The
// structpb.Value NumberValue is float64-backed, so anything beyond
// this loses precision silently. We refuse to encode integers
// outside this range rather than corrupting the value.
const maxSafeInteger = int64(1) << 53

// MapToStruct converts a Go map[string]any to a *structpb.Struct.
//
// See package doc for the encode contract. Errors out on:
//   - Unsupported value type (custom struct, channel, function)
//   - int64/uint64 magnitude > 2^53 (precision-loss avoidance)
//   - Nesting > maxNestingDepth (DoS guard)
func MapToStruct(m map[string]any) (*structpb.Struct, error) {
	return mapToStructDepth(m, 0)
}

// MustMapToStruct is the panicking variant for test fixtures.
// Production code MUST NOT use this — handlers receive untrusted
// data and need to surface errors to the engine.
func MustMapToStruct(m map[string]any) *structpb.Struct {
	s, err := MapToStruct(m)
	if err != nil {
		panic(fmt.Sprintf("wirev1.MustMapToStruct: %v", err))
	}
	return s
}

// StructToMap converts a *structpb.Struct to map[string]any,
// reversing MapToStruct's encoding. See package doc for the
// type-widening contract (all integers → int64 on round-trip;
// time.Time → string on round-trip).
func StructToMap(s *structpb.Struct) (map[string]any, error) {
	return structToMapDepth(s, 0)
}

// DecodeTime is a helper for handlers that need to recover a
// time.Time from a round-tripped map. Returns an error if the
// key is absent, the value isn't a string, or the string isn't
// parseable as RFC3339Nano. Use in handler code instead of
// `m[key].(time.Time)` post-round-trip.
func DecodeTime(m map[string]any, key string) (time.Time, error) {
	v, ok := m[key]
	if !ok {
		return time.Time{}, fmt.Errorf("wirev1.DecodeTime: key %q absent", key)
	}
	s, ok := v.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("wirev1.DecodeTime: key %q is %T, want string (RFC3339Nano)", key, v)
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("wirev1.DecodeTime: key %q: %w", key, err)
	}
	return t, nil
}

// ValidateSchemaVersion returns an error for any value other than
// the current wirev1 schema version (1). L-012 will call this on
// every inbound message to detect controller↔agent skew; wiring
// the contract at L-007 means L-012 inherits a validated pattern
// rather than designing one under deadline.
func ValidateSchemaVersion(v uint32) error {
	if v != 1 {
		return fmt.Errorf("wirev1: unsupported schema_version %d (this build speaks 1)", v)
	}
	return nil
}

func mapToStructDepth(m map[string]any, depth int) (*structpb.Struct, error) {
	if depth >= maxNestingDepth {
		return nil, fmt.Errorf("wirev1: map nesting exceeds %d levels (DoS guard)", maxNestingDepth)
	}
	if m == nil {
		return &structpb.Struct{Fields: map[string]*structpb.Value{}}, nil
	}
	fields := make(map[string]*structpb.Value, len(m))
	for k, v := range m {
		val, err := toValue(v, depth+1)
		if err != nil {
			return nil, fmt.Errorf("MapToStruct: key %q: %w", k, err)
		}
		fields[k] = val
	}
	return &structpb.Struct{Fields: fields}, nil
}

func structToMapDepth(s *structpb.Struct, depth int) (map[string]any, error) {
	if depth >= maxNestingDepth {
		return nil, fmt.Errorf("wirev1: struct nesting exceeds %d levels (DoS guard)", maxNestingDepth)
	}
	if s == nil {
		return nil, nil
	}
	out := make(map[string]any, len(s.Fields))
	for k, v := range s.Fields {
		decoded, err := fromValue(v, depth+1)
		if err != nil {
			return nil, fmt.Errorf("StructToMap: key %q: %w", k, err)
		}
		out[k] = decoded
	}
	return out, nil
}

// toValue encodes a single Go value into a structpb.Value. The
// type switch order matters: time.Time is checked before generic
// reflect-friendly types because the api types embed it commonly
// (PreState.CapturedAt, etc.) and operators already expect RFC3339.
func toValue(v any, depth int) (*structpb.Value, error) {
	switch x := v.(type) {
	case nil:
		return structpb.NewNullValue(), nil
	case string:
		return structpb.NewStringValue(x), nil
	case bool:
		return structpb.NewBoolValue(x), nil
	case time.Time:
		return structpb.NewStringValue(x.UTC().Format(time.RFC3339Nano)), nil
	case int:
		return safeIntValue(int64(x))
	case int8:
		return structpb.NewNumberValue(float64(x)), nil
	case int16:
		return structpb.NewNumberValue(float64(x)), nil
	case int32:
		return structpb.NewNumberValue(float64(x)), nil
	case int64:
		return safeIntValue(x)
	case uint:
		return safeUintValue(uint64(x))
	case uint8:
		return structpb.NewNumberValue(float64(x)), nil
	case uint16:
		return structpb.NewNumberValue(float64(x)), nil
	case uint32:
		return structpb.NewNumberValue(float64(x)), nil
	case uint64:
		return safeUintValue(x)
	case float32:
		return structpb.NewNumberValue(float64(x)), nil
	case float64:
		return structpb.NewNumberValue(x), nil
	case map[string]any:
		inner, err := mapToStructDepth(x, depth)
		if err != nil {
			return nil, err
		}
		return structpb.NewStructValue(inner), nil
	case []any:
		return listToValue(x, depth)
	case []string:
		conv := make([]any, len(x))
		for i, s := range x {
			conv[i] = s
		}
		return listToValue(conv, depth)
	case []int:
		conv := make([]any, len(x))
		for i, n := range x {
			conv[i] = n
		}
		return listToValue(conv, depth)
	case []map[string]any:
		conv := make([]any, len(x))
		for i, m := range x {
			conv[i] = m
		}
		return listToValue(conv, depth)
	default:
		return nil, fmt.Errorf("wirev1: unsupported value type %T (supported: nil, string, bool, time.Time, numerics, map[string]any, []any/[]string/[]int/[]map[string]any)", v)
	}
}

// safeIntValue encodes int/int64 as a structpb NumberValue, refusing
// values whose magnitude exceeds 2^53. Above that threshold, float64
// can no longer represent every integer exactly; encoding would
// silently lose precision (e.g., 2^53+1 → 2^53). Handlers that need
// larger integers should encode as strings explicitly.
func safeIntValue(n int64) (*structpb.Value, error) {
	if n > maxSafeInteger || n < -maxSafeInteger {
		return nil, fmt.Errorf("wirev1: int64 value %d exceeds float64-safe range [%d, %d]; encode as string to preserve precision", n, -maxSafeInteger, maxSafeInteger)
	}
	return structpb.NewNumberValue(float64(n)), nil
}

func safeUintValue(n uint64) (*structpb.Value, error) {
	if n > uint64(maxSafeInteger) {
		return nil, fmt.Errorf("wirev1: uint64 value %d exceeds float64-safe range [0, %d]; encode as string to preserve precision", n, maxSafeInteger)
	}
	return structpb.NewNumberValue(float64(n)), nil
}

// fromValue decodes a single structpb.Value back to a Go-native
// value. Numerics decode as int64 when the value is integral and
// fits in [-2^53, 2^53]; float64 otherwise. This matches the safe
// encode range — any value the encoder accepted round-trips
// losslessly; values outside that range (which the encoder would
// have rejected) come back as float64 so the precision-loss is
// at least visible in the type.
func fromValue(v *structpb.Value, depth int) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch kind := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return nil, nil
	case *structpb.Value_StringValue:
		return kind.StringValue, nil
	case *structpb.Value_BoolValue:
		return kind.BoolValue, nil
	case *structpb.Value_NumberValue:
		n := kind.NumberValue
		// Integer-round-trip range: [-2^53, 2^53]. Above 2^53 the
		// float64 has fewer than 1 ULP between adjacent integers,
		// so the heuristic `n == float64(int64(n))` would still
		// return true but the int64 value would not be the
		// original — silent corruption. Hard-bound the range.
		if n == float64(int64(n)) && n >= float64(-maxSafeInteger) && n <= float64(maxSafeInteger) {
			return int64(n), nil
		}
		return n, nil
	case *structpb.Value_StructValue:
		return structToMapDepth(kind.StructValue, depth)
	case *structpb.Value_ListValue:
		return listFromValue(kind.ListValue, depth)
	default:
		return nil, fmt.Errorf("wirev1: unknown structpb.Value kind: %T", kind)
	}
}

func listToValue(xs []any, depth int) (*structpb.Value, error) {
	if depth >= maxNestingDepth {
		return nil, fmt.Errorf("wirev1: list nesting exceeds %d levels (DoS guard)", maxNestingDepth)
	}
	values := make([]*structpb.Value, len(xs))
	for i, x := range xs {
		val, err := toValue(x, depth+1)
		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		values[i] = val
	}
	return structpb.NewListValue(&structpb.ListValue{Values: values}), nil
}

func listFromValue(lv *structpb.ListValue, depth int) ([]any, error) {
	if depth >= maxNestingDepth {
		return nil, fmt.Errorf("wirev1: list nesting exceeds %d levels (DoS guard)", maxNestingDepth)
	}
	if lv == nil {
		return nil, nil
	}
	out := make([]any, len(lv.Values))
	for i, v := range lv.Values {
		decoded, err := fromValue(v, depth+1)
		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		out[i] = decoded
	}
	return out, nil
}
