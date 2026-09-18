package engine

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// TestPayloadCopy_SupportedTypes covers every value shape the corpus
// produces: handler literals (string, bool, nested maps, []any, []string)
// and the decode-side shapes the SQLite reload and the agent wire format
// normalize to (float64, []any, map[string]any).
func TestPayloadCopy_SupportedTypes(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	in := map[string]any{
		"string":    "value",
		"bool":      true,
		"int":       42,
		"float":     3.5,
		"number":    json.Number("9007199254740993"),
		"nil":       nil,
		"strings":   []string{"a", "b"},
		"anys":      []any{"a", 1, map[string]any{"deep": "x"}},
		"nested":    map[string]any{"inner": map[string]any{"deeper": "y"}},
		"empty_map": map[string]any{},
	}
	out, err := copyStringKeyedMap(in, "data")
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("copy differs from source:\n got %#v\nwant %#v", out, in)
	}
	for k, v := range in {
		if got, want := reflect.TypeOf(out[k]), reflect.TypeOf(v); got != want {
			t.Errorf("key %q: type changed %v -> %v", k, want, got)
		}
	}
}

// TestPayloadCopy_NumericPrecision locks the reason the copy is a typed
// switch and not a JSON round trip: a round trip widens integers to
// float64 and loses exactness above 2^53.
func TestPayloadCopy_NumericPrecision(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	const big = int64(1<<53) + 1
	out, err := copyStringKeyedMap(map[string]any{"big": big}, "data")
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	got, ok := out["big"].(int64)
	if !ok {
		t.Fatalf("value changed type: %T", out["big"])
	}
	if got != big {
		t.Errorf("precision lost: got %d want %d", got, big)
	}
}

// TestPayloadCopy_NestedIsolation proves the copy is deep: writing through
// the source must not reach the copy at any level.
func TestPayloadCopy_NestedIsolation(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	inner := map[string]any{"inner": "original"}
	list := []any{map[string]any{"element": "original"}}
	strs := []string{"original"}
	in := map[string]any{"nested": inner, "list": list, "strings": strs}

	out, err := copyStringKeyedMap(in, "data")
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	inner["inner"] = "mutated"
	list[0].(map[string]any)["element"] = "mutated"
	strs[0] = "mutated"

	if out["nested"].(map[string]any)["inner"] != "original" {
		t.Error("nested map is shared with the source")
	}
	if out["list"].([]any)[0].(map[string]any)["element"] != "original" {
		t.Error("map inside a slice is shared with the source")
	}
	if out["strings"].([]string)[0] != "original" {
		t.Error("[]string is shared with the source")
	}
}

// TestPayloadCopy_UnsupportedFailsClosed proves an unknown type is an
// error, never a retained alias. A silent fallback would reintroduce the
// defect this layer removes.
func TestPayloadCopy_UnsupportedFailsClosed(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	type custom struct{ A int }
	cases := map[string]any{
		"typed_map":   map[string]string{"a": "b"},
		"typed_slice": []int{1, 2},
		"struct":      custom{A: 1},
		"pointer":     &custom{A: 1},
		"channel":     make(chan int),
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := copyStringKeyedMap(map[string]any{name: v}, "data")
			if err == nil {
				t.Fatalf("unsupported %T copied instead of failing: %#v", v, out)
			}
			if out != nil {
				t.Error("a failed copy must not return a partial map")
			}
			if !strings.Contains(err.Error(), "data."+name) {
				t.Errorf("error does not name the key path: %v", err)
			}
		})
	}
}

// TestPayloadCopy_PreStateDiagnosticSubstitution proves one bad entry does
// not erase the rest of the bundle, and that the stand-in carries no
// reference to the original state.
func TestPayloadCopy_PreStateDiagnosticSubstitution(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	bad := map[string]any{"typed": map[string]string{"a": "b"}}
	in := []api.PreState{
		{StepIndex: 0, Mechanism: "good", Data: map[string]any{"k": "v"}},
		{StepIndex: 1, Mechanism: "bad", Data: bad},
	}
	out, err := copyPreStates(in)
	if err == nil {
		t.Fatal("expected an error for the unrepresentable entry")
	}
	if out[0].Data["k"] != "v" {
		t.Error("a clean entry was discarded because a sibling failed")
	}
	if out[1].Data["kensa_state_unrepresentable"] != "true" {
		t.Errorf("no diagnostic recorded: %#v", out[1].Data)
	}
	if out[1].Data["step_index"] != "1" || out[1].Data["mechanism"] != "bad" {
		t.Errorf("diagnostic lost the entry's identity: %#v", out[1].Data)
	}
	if _, kept := out[1].Data["typed"]; kept {
		t.Error("diagnostic entry retained the unsupported value")
	}
}

// TestPayloadCopy_ElementTypes is the standing check behind copying
// StepResult, RollbackResult, ValidatorResult and FrameworkRef with a
// plain slice copy: it holds only while those types stay free of
// reference-typed fields. If someone adds a map or slice field, this
// fails and the copy must become recursive.
func TestPayloadCopy_ElementTypes(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	for _, typ := range []reflect.Type{
		reflect.TypeOf(api.StepResult{}),
		reflect.TypeOf(api.RollbackResult{}),
		reflect.TypeOf(api.ValidatorResult{}),
		reflect.TypeOf(api.FrameworkRef{}),
	} {
		for i := range typ.NumField() {
			f := typ.Field(i)
			switch f.Type.Kind() {
			case reflect.Map, reflect.Slice, reflect.Pointer, reflect.Interface, reflect.Chan, reflect.Func:
				t.Errorf("%s.%s is %s: a slice copy no longer copies this type fully",
					typ.Name(), f.Name, f.Type.Kind())
			}
		}
	}
}
