package wirev1

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

// TestMapToStruct_Domain locks AC-03: the bridge accepts the full
// domain of api.PreState.Data and api.Params values without
// returning an error. Each case here represents a value shape
// kensa handlers actually emit today.
//
// @spec agent-wire-protocol
// @ac AC-03
func TestMapToStruct_Domain(t *testing.T) {
	t.Log("// @spec agent-wire-protocol")
	t.Log("// @ac AC-03")
	cases := []struct {
		name string
		in   map[string]any
	}{
		{"empty", map[string]any{}},
		{"nil_value", map[string]any{"x": nil}},
		{"string", map[string]any{"path": "/etc/ssh/sshd_config"}},
		{"bool", map[string]any{"strict_modes": true}},
		{"int", map[string]any{"line": 42}},
		{"int64", map[string]any{"size": int64(1 << 40)}},
		{"uint32", map[string]any{"mode": uint32(0o644)}},
		{"float64", map[string]any{"ratio": 0.875}},
		{"time", map[string]any{"captured_at": time.Date(2026, 5, 11, 9, 12, 0, 0, time.UTC)}},
		{"nested", map[string]any{"outer": map[string]any{"inner": "hello"}}},
		{"list_any", map[string]any{"items": []any{"a", 1, true, nil}}},
		{"list_string", map[string]any{"tags": []string{"cis", "stig"}}},
		{"list_map", map[string]any{"rules": []map[string]any{{"id": "r1"}, {"id": "r2"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := MapToStruct(tc.in)
			if err != nil {
				t.Fatalf("MapToStruct: %v", err)
			}
			if s == nil {
				t.Fatal("expected non-nil Struct")
			}
		})
	}
}

// TestBridge_Roundtrip locks AC-04: StructToMap(MapToStruct(M)) == M
// for value domains the helpers claim to support. Critical because
// the wire layer round-trips through this pair on every handler
// invocation — a drift here corrupts handler-visible data.
//
// @spec agent-wire-protocol
// @ac AC-04
func TestBridge_Roundtrip(t *testing.T) {
	t.Log("// @spec agent-wire-protocol")
	t.Log("// @ac AC-04")
	cases := []struct {
		name string
		in   map[string]any
		// want is the expected output after round-trip. Differs
		// from `in` for numeric types because all numbers go through
		// float64 on the wire — integers come back as int64 via the
		// fromValue heuristic, but type-narrowed inputs (int, int32,
		// uint32) widen to int64.
		want map[string]any
	}{
		{
			"strings_and_bools_passthrough",
			map[string]any{"path": "/etc", "ok": true, "missing": nil},
			map[string]any{"path": "/etc", "ok": true, "missing": nil},
		},
		{
			"int_widens_to_int64",
			map[string]any{"line": 42},
			map[string]any{"line": int64(42)},
		},
		{
			"int64_at_max_safe_preserved",
			map[string]any{"n": int64(maxSafeInteger)},
			map[string]any{"n": int64(maxSafeInteger)},
		},
		{
			"uint32_widens_to_int64",
			map[string]any{"mode": uint32(0o644)},
			map[string]any{"mode": int64(0o644)},
		},
		{
			"non_integer_float_preserved",
			map[string]any{"ratio": 0.875},
			map[string]any{"ratio": 0.875},
		},
		{
			"nested_struct",
			map[string]any{"a": map[string]any{"b": "c"}},
			map[string]any{"a": map[string]any{"b": "c"}},
		},
		{
			"list_of_strings",
			map[string]any{"tags": []string{"x", "y"}},
			// []string normalizes to []any{"x", "y"} on round-trip.
			map[string]any{"tags": []any{"x", "y"}},
		},
		{
			"list_of_ints",
			map[string]any{"ids": []int{1, 2, 3}},
			map[string]any{"ids": []any{int64(1), int64(2), int64(3)}},
		},
		{
			"mixed_list",
			map[string]any{"items": []any{"a", int64(1), true, nil}},
			map[string]any{"items": []any{"a", int64(1), true, nil}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := MapToStruct(tc.in)
			if err != nil {
				t.Fatalf("MapToStruct: %v", err)
			}
			got, err := StructToMap(s)
			if err != nil {
				t.Fatalf("StructToMap: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("roundtrip mismatch\n  got:  %#v\n  want: %#v", got, tc.want)
			}
		})
	}
}

// TestBridge_TimeRoundtrip locks the documented asymmetry: time.Time
// inputs encode as RFC3339Nano strings, and the decoded value comes
// back as a string (not time.Time). Handler authors who previously
// type-asserted .(time.Time) on PreState.Data after agent round-trip
// must use DecodeTime or time.Parse.
func TestBridge_TimeRoundtrip(t *testing.T) {
	when := time.Date(2026, 5, 11, 9, 12, 34, 567890000, time.UTC)
	in := map[string]any{"captured_at": when}

	s, err := MapToStruct(in)
	if err != nil {
		t.Fatalf("MapToStruct: %v", err)
	}
	got, err := StructToMap(s)
	if err != nil {
		t.Fatalf("StructToMap: %v", err)
	}
	wantStr := when.Format(time.RFC3339Nano)
	if got["captured_at"] != wantStr {
		t.Errorf("captured_at: got %v (%T), want %q (string)", got["captured_at"], got["captured_at"], wantStr)
	}

	// DecodeTime smooths the asymmetry for handlers that need
	// back the time.Time value.
	recovered, err := DecodeTime(got, "captured_at")
	if err != nil {
		t.Fatalf("DecodeTime: %v", err)
	}
	if !recovered.Equal(when) {
		t.Errorf("DecodeTime returned %v, want %v", recovered, when)
	}
}

// TestDecodeTime_Errors locks the helper's failure modes so
// handlers get diagnosable error messages.
func TestDecodeTime_Errors(t *testing.T) {
	cases := []struct {
		name string
		m    map[string]any
		key  string
	}{
		{"missing_key", map[string]any{"other": "value"}, "absent"},
		{"wrong_type", map[string]any{"t": 42}, "t"},
		{"bad_string", map[string]any{"t": "not a timestamp"}, "t"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeTime(tc.m, tc.key)
			if err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

// TestMapToStruct_TimeAsRFC3339 locks the time.Time → RFC3339Nano
// string contract from C-03. Operators already see RFC3339 timestamps
// in evidence envelopes; the wire format must not silently switch
// representations.
func TestMapToStruct_TimeAsRFC3339(t *testing.T) {
	when := time.Date(2026, 5, 11, 9, 12, 34, 567890000, time.UTC)
	s, err := MapToStruct(map[string]any{"at": when})
	if err != nil {
		t.Fatalf("MapToStruct: %v", err)
	}
	got := s.Fields["at"].GetStringValue()
	want := when.Format(time.RFC3339Nano)
	if got != want {
		t.Errorf("time encoding: got %q, want %q", got, want)
	}
}

// TestMapToStruct_RejectsUnsupportedTypes locks the
// fail-loud-on-unknown-type behavior from C-03. Silently dropping
// or stringifying an unsupported type would corrupt handler data
// without any signal to the developer.
func TestMapToStruct_RejectsUnsupportedTypes(t *testing.T) {
	type customStruct struct{ X int }
	cases := []struct {
		name string
		in   any
	}{
		{"custom_struct", customStruct{X: 1}},
		{"channel", make(chan int)},
		{"function", func() {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MapToStruct(map[string]any{"bad": tc.in})
			if err == nil {
				t.Errorf("expected error for type %T, got nil", tc.in)
			}
			if err != nil && !strings.Contains(err.Error(), "unsupported value type") {
				t.Errorf("error should mention unsupported value type; got: %v", err)
			}
		})
	}
}

// TestMapToStruct_RejectsOversizedIntegers locks the 2^53 safety
// guard added in security review: integers whose magnitude exceeds
// float64's safe-integer range MUST fail loudly at encode time, not
// silently corrupt to a nearby representable value.
//
// Concrete kensa example: time.Now().UnixNano() is ~1.76e18, well
// above 2^53. A handler emitting Data["captured_unix_nano"] = ...
// (with a raw int64 nanosecond timestamp) would silently lose
// precision under the old bounds.
func TestMapToStruct_RejectsOversizedIntegers(t *testing.T) {
	cases := []struct {
		name string
		in   any
	}{
		{"int64_above_2^53", int64(maxSafeInteger + 1)},
		{"int64_min_int64", int64(-1 << 62)},
		{"uint64_above_2^53", uint64(maxSafeInteger + 1)},
		{"uint64_max", uint64(1<<64 - 1)},
		{"int_above_2^53", int(maxSafeInteger + 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MapToStruct(map[string]any{"big": tc.in})
			if err == nil {
				t.Errorf("expected error for %T %v (exceeds 2^53), got nil", tc.in, tc.in)
			}
			if err != nil && !strings.Contains(err.Error(), "float64-safe range") {
				t.Errorf("error should mention float64-safe range; got: %v", err)
			}
		})
	}
}

// TestMapToStruct_RejectsDeepNesting locks the DoS guard. A
// malicious controller (or man-in-the-middle on compromised SSH)
// could send a Request with a 250K-deep payload; without this
// bound, the agent's goroutine stack blows up.
func TestMapToStruct_RejectsDeepNesting(t *testing.T) {
	// Build a map nested deeper than the limit.
	deep := map[string]any{}
	cur := deep
	for i := 0; i < maxNestingDepth+5; i++ {
		next := map[string]any{}
		cur["nest"] = next
		cur = next
	}
	_, err := MapToStruct(deep)
	if err == nil {
		t.Error("expected error for over-deep nesting, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "nesting exceeds") {
		t.Errorf("error should mention nesting limit; got: %v", err)
	}
}

// TestStructToMap_RejectsDeepNesting mirrors the encode-side guard
// on the decode side. A peer sending a deeply-nested Struct (which
// protobuf's wire format CAN encode within its own size limits) must
// not crash the agent on decode.
func TestStructToMap_RejectsDeepNesting(t *testing.T) {
	// Construct a structpb.Struct nested past the limit by hand
	// — can't go through MapToStruct since that would also reject.
	build := func(d int) *structpb.Struct {
		root := &structpb.Struct{Fields: map[string]*structpb.Value{}}
		cur := root
		for i := 0; i < d; i++ {
			next := &structpb.Struct{Fields: map[string]*structpb.Value{}}
			cur.Fields["nest"] = structpb.NewStructValue(next)
			cur = next
		}
		return root
	}
	_, err := StructToMap(build(maxNestingDepth + 5))
	if err == nil {
		t.Error("expected error for over-deep nesting on decode, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "nesting exceeds") {
		t.Errorf("error should mention nesting limit; got: %v", err)
	}
}

// TestMapToStruct_NilMap locks the nil-input contract: a nil map
// is valid input (handlers may legitimately have no captured data)
// and produces a valid empty *structpb.Struct, not an error.
func TestMapToStruct_NilMap(t *testing.T) {
	s, err := MapToStruct(nil)
	if err != nil {
		t.Fatalf("MapToStruct(nil): %v", err)
	}
	if s == nil {
		t.Fatal("MapToStruct(nil) returned nil Struct")
	}
	if len(s.Fields) != 0 {
		t.Errorf("MapToStruct(nil): want empty Fields, got %d", len(s.Fields))
	}
}

// TestStructToMap_NilStruct locks the reverse: nil input → nil
// output, no error.
func TestStructToMap_NilStruct(t *testing.T) {
	got, err := StructToMap(nil)
	if err != nil {
		t.Fatalf("StructToMap(nil): %v", err)
	}
	if got != nil {
		t.Errorf("StructToMap(nil): want nil, got %#v", got)
	}
}

// TestMustMapToStruct_PanicsOnError documents the panic-on-error
// behavior of the test-fixture helper, so anyone using it knows it
// is NOT safe for production code paths.
func TestMustMapToStruct_PanicsOnError(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustMapToStruct should have panicked on unsupported type")
		}
	}()
	_ = MustMapToStruct(map[string]any{"bad": make(chan int)})
}

// TestValidateSchemaVersion locks the contract L-012 will call on
// every inbound message. Wired at L-007 so L-012 doesn't have to
// design version-skew handling under deadline.
//
// @spec agent-wire-protocol
// @ac AC-06
func TestValidateSchemaVersion(t *testing.T) {
	t.Log("// @spec agent-wire-protocol")
	t.Log("// @ac AC-06")
	if err := ValidateSchemaVersion(1); err != nil {
		t.Errorf("ValidateSchemaVersion(1): expected nil error, got %v", err)
	}
	for _, bad := range []uint32{0, 2, 100, 1<<32 - 1} {
		if err := ValidateSchemaVersion(bad); err == nil {
			t.Errorf("ValidateSchemaVersion(%d): expected error, got nil", bad)
		}
	}
}
