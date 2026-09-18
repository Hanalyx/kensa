package engine

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/redact"
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

// TestPayloadCopy_NilnessPreserved locks the difference between a typed
// nil slice and an empty one. Turning nil into an empty slice changes the
// captured state's JSON from null to [], which changes both the signed
// bytes and what a reader sees.
func TestPayloadCopy_NilnessPreserved(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	var nilStrings []string
	var nilAnys []any
	in := map[string]any{
		"nil_strings":   nilStrings,
		"nil_anys":      nilAnys,
		"empty_strings": []string{},
		"empty_anys":    []any{},
		"nil_map":       map[string]any(nil),
	}
	out, err := copyStringKeyedMap(in, "data")
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	want, _ := json.Marshal(in)
	got, _ := json.Marshal(out)
	if string(got) != string(want) {
		t.Errorf("nilness changed:\n got %s\nwant %s", got, want)
	}
	if out["nil_strings"].([]string) != nil {
		t.Error("typed nil []string became non-nil")
	}
	if out["nil_anys"].([]any) != nil {
		t.Error("typed nil []any became non-nil")
	}
	if out["empty_strings"].([]string) == nil {
		t.Error("empty []string became nil")
	}
	if out["empty_anys"].([]any) == nil {
		t.Error("empty []any became nil")
	}
}

// TestEvidenceEnvelope_OwnsEverySourceField mutates each of the six
// mutable inputs independently and asserts none of them reaches the
// envelope. Signature verification cannot stand in for this: RollbackResults
// is outside the v1 canonical form, so tampering with it would verify
// cleanly, and PostStateBundle and ValidatorResults are not reachable from
// the returned result at all.
func TestEvidenceEnvelope_OwnsEverySourceField(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	const original = "original"
	const mutated = "mutated after construction"

	steps := []api.StepResult{{StepIndex: 0, Detail: original}}
	pre := []api.PreState{{StepIndex: 0, Data: map[string]any{
		"k":      original,
		"nested": map[string]any{"inner": original},
	}}}
	post := []api.PreState{{StepIndex: 0, Data: map[string]any{"k": original}}}
	validators := []api.ValidatorResult{{Name: original}}
	rollbacks := []api.RollbackResult{{StepIndex: 0, Detail: original}}
	txn := &api.Transaction{FrameworkRefs: []api.FrameworkRef{{FrameworkID: original}}}

	env, err := evidenceEnvelope(txn, time.Now(), time.Now(), api.StatusCommitted,
		steps, pre, validators, rollbacks, post)
	if err != nil {
		t.Fatalf("evidenceEnvelope: %v", err)
	}

	steps[0].Detail = mutated
	pre[0].Data["k"] = mutated
	pre[0].Data["nested"].(map[string]any)["inner"] = mutated
	post[0].Data["k"] = mutated
	validators[0].Name = mutated
	rollbacks[0].Detail = mutated
	txn.FrameworkRefs[0].FrameworkID = mutated

	checks := []struct {
		field string
		got   any
	}{
		{"ApplySteps", env.ApplySteps[0].Detail},
		{"PreStateBundle", env.PreStateBundle[0].Data["k"]},
		{"PreStateBundle (nested)", env.PreStateBundle[0].Data["nested"].(map[string]any)["inner"]},
		{"PostStateBundle", env.PostStateBundle[0].Data["k"]},
		{"ValidatorResults", env.ValidatorResults[0].Name},
		{"RollbackResults", env.RollbackResults[0].Detail},
		{"FrameworkRefs", env.FrameworkRefs[0].FrameworkID},
	}
	for _, c := range checks {
		if c.got != original {
			t.Errorf("%s: envelope shares its source (got %v)", c.field, c.got)
		}
	}
}

// TestEvidenceEnvelope_RedactsOwnedBundles proves the envelope is redacted
// at construction rather than as a side effect of signing, so evidence that
// never reaches a successful Sign still carries no credential value. The
// source maps must stay verbatim: they are the rollback restoration source.
func TestEvidenceEnvelope_RedactsOwnedBundles(t *testing.T) {
	t.Log("// @spec store-redaction")
	t.Log("// @ac AC-04")
	const secret = "s3cr3t-value" // pragma: allowlist secret
	pre := []api.PreState{{Data: map[string]any{
		"nested": map[string]any{"password": secret},
	}}}
	post := []api.PreState{{Data: map[string]any{"api_key": secret}}}

	env, err := evidenceEnvelope(&api.Transaction{}, time.Now(), time.Now(),
		api.StatusCommitted, nil, pre, nil, nil, post)
	if err != nil {
		t.Fatalf("evidenceEnvelope: %v", err)
	}
	if got := env.PreStateBundle[0].Data["nested"].(map[string]any)["password"]; got != redact.Placeholder {
		t.Errorf("nested pre-state credential not redacted: got %v", got)
	}
	if got := env.PostStateBundle[0].Data["api_key"]; got != redact.Placeholder {
		t.Errorf("post-state credential not redacted: got %v", got)
	}
	if got := pre[0].Data["nested"].(map[string]any)["password"]; got != secret {
		t.Errorf("source pre-state was redacted in place: got %v", got)
	}
	if got := post[0].Data["api_key"]; got != secret {
		t.Errorf("source post-state was redacted in place: got %v", got)
	}
}
