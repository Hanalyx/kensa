package engine_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
)

// reservedPlanFields names every exported [api.Plan] field the planner does
// NOT populate, with the reason. A field belongs here only while its doc
// comment in api/planner.go says the same thing: this map and that comment
// are the declaration, and TestPlanPopulatesEveryDeclaredField is the
// independent derivation that keeps them honest.
//
// Removing a field from this map is how you promote it to "populated". Adding
// one is a deliberate statement that consumers must not read it yet, and it
// should be rare enough to argue about in review.
var reservedPlanFields = map[string]string{
	"HostID": "the planner does not receive the host identity; the caller " +
		"knows which host it planned against",
	"Capabilities": "capability detection runs on the scan path, not the plan " +
		"path; the planner has no CapabilitySet to record",
	"Validators": "the validate phase re-runs the rule's own check rather than " +
		"a separately enumerated validator set, so there is nothing to preview",
}

// TestPlanPopulatesEveryDeclaredField is the drift guard for the
// declared-but-empty class.
//
// api.Plan is a contract. Every exported field on it is a promise to a
// consumer, and its doc comment states that promise in the affirmative. A
// field that is always the zero value breaks the promise silently: a consumer
// reading it cannot tell "no validators for this rule" from "this is not
// implemented", and OpenWatch shipped a plan-preview panel that told operators
// nothing verifies a fix, for every rule, because Validators is always nil
// (KN-OW-017).
//
// The failure mode is structural rather than a mistake anyone made: nothing
// connected the field's existence to the code that fills it. This test is that
// connection. Every exported field must be populated by a real
// PlanTransaction call, or named in reservedPlanFields with a reason.
//
// Fields are checked against SEVERAL representative plans rather than one,
// because a bool that is legitimately false and a bool nobody assigns are the
// same value. A field passes if any representative plan populates it.
//
// @spec engine-plan-field-population
// @ac AC-01
func TestPlanPopulatesEveryDeclaredField(t *testing.T) {
	t.Run("engine-plan-field-population/AC-01", func(t *testing.T) {})

	plans := representativePlans(t)

	typ := reflect.TypeOf(api.Plan{})
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		populated := false
		for _, p := range plans {
			if isPopulated(reflect.ValueOf(*p).Field(i)) {
				populated = true
				break
			}
		}

		reason, reserved := reservedPlanFields[field.Name]
		switch {
		case populated && reserved:
			t.Errorf("api.Plan.%s is listed as reserved (%q) but the planner populates it: "+
				"remove it from reservedPlanFields and correct its doc comment in api/planner.go",
				field.Name, reason)
		case !populated && !reserved:
			t.Errorf("api.Plan.%s is never populated by PlanTransaction, and its doc comment "+
				"promises otherwise. Either populate it, or add it to reservedPlanFields with a "+
				"reason and amend the doc comment to say it is reserved. A declared field that "+
				"always carries the zero value reads to a consumer as a fact about the host.",
				field.Name)
		}
	}
}

// TestReservedPlanFieldsAreDocumented keeps the two halves of the declaration
// from drifting. A field may be reserved, but api/planner.go has to say so,
// because the doc comment is what a consumer reads.
//
// @spec engine-plan-field-population
// @ac AC-02
func TestReservedPlanFieldsAreDocumented(t *testing.T) {
	t.Run("engine-plan-field-population/AC-02", func(t *testing.T) {})

	for name := range reservedPlanFields {
		t.Run(name, func(t *testing.T) {
			doc := planFieldDoc(t, name)
			if doc == "" {
				t.Fatalf("no doc comment found for api.Plan.%s", name)
			}
			if !containsAny(doc, "reserved", "not populated", "always empty") {
				t.Errorf("api.Plan.%s is reserved but its doc comment does not say so:\n  %s\n"+
					"A consumer reading only the comment would expect a value.", name, doc)
			}
		})
	}
}

// representativePlans returns plans covering the input shapes the planner
// branches on, so a field that is only populated for one shape still counts.
func representativePlans(t *testing.T) []*api.Plan {
	t.Helper()

	// Capturable and control-channel-sensitive: populates PreStates,
	// RollbackPlan, Transactional and ControlChannelSensitive.
	ccHandler := &engine.FakeHandler{HandlerName: "service_enabled", IsCapturable: true}
	capturable := planFor(t, ccHandler, &api.Rule{
		ID:            "representative-capturable",
		Transactional: true,
		Implementations: []api.Implementation{{
			Default: true,
			Remediation: api.Remediation{
				Mechanism: "service_enabled",
				Params:    api.Params{"name": "auditd"},
			},
		}},
	})

	// Non-capturable and non-transactional: populates Warnings.
	escapeHatch := &engine.FakeHandler{HandlerName: "command_exec", IsCapturable: false}
	nonCapturable := planFor(t, escapeHatch, &api.Rule{
		ID:            "representative-escape-hatch",
		Transactional: false,
		Implementations: []api.Implementation{{
			Default: true,
			Remediation: api.Remediation{
				Mechanism: "command_exec",
				Params:    api.Params{"command": "true"},
			},
		}},
	})

	return []*api.Plan{capturable, nonCapturable}
}

func planFor(t *testing.T, h api.Handler, rule *api.Rule) *api.Plan {
	t.Helper()
	e := newPlanTestEngine(t, h)
	plan, err := e.PlanTransaction(context.Background(), engine.NewFakeTransport(), rule)
	if err != nil {
		t.Fatalf("PlanTransaction(%s): %v", rule.ID, err)
	}
	return plan
}

// planFieldDoc returns the doc comment attached to the named field of
// api.Plan, read from source. Reading the comment rather than trusting a
// second copy of it is the point: the comment is what a consumer sees.
func planFieldDoc(t *testing.T, fieldName string) string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "..", "api", "planner.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse api/planner.go: %v", err)
	}

	var doc string
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Plan" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, f := range st.Fields.List {
			for _, name := range f.Names {
				if name.Name == fieldName && f.Doc != nil {
					doc = f.Doc.Text()
				}
			}
		}
		return false
	})
	return doc
}

// containsAny reports whether s contains any of subs, case-insensitively.
func containsAny(s string, subs ...string) bool {
	s = strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// isPopulated reports whether a field carries information.
//
// reflect.Value.IsZero is not the right test on its own: an empty but non-nil
// map or slice is not the zero value, yet it tells a consumer nothing. The
// planner assigns api.CapabilitySet{} to Plan.Capabilities, which IsZero calls
// populated and an operator would call empty. Length is the honest measure for
// collections and strings.
func isPopulated(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Map, reflect.Slice, reflect.String:
		return v.Len() > 0
	default:
		return !v.IsZero()
	}
}

// TestEmptyCollectionsCountAsUnpopulated pins the measure of "populated".
//
// reflect.Value.IsZero is the obvious choice and the wrong one. The planner
// assigns api.CapabilitySet{} to Plan.Capabilities: an empty, non-nil map,
// which is not the zero value and therefore passes an IsZero check, while
// carrying exactly as much information as nil. The first version of the
// population guard used IsZero and reported Capabilities as populated, which
// is how a field that has never held a value would have kept its affirmative
// doc comment.
//
// @spec engine-plan-field-population
// @ac AC-03
func TestEmptyCollectionsCountAsUnpopulated(t *testing.T) {
	t.Run("engine-plan-field-population/AC-03", func(t *testing.T) {})

	for _, tc := range []struct {
		name string
		v    any
		want bool
	}{
		{"empty non-nil map (the Capabilities case)", api.CapabilitySet{}, false},
		{"nil map", api.CapabilitySet(nil), false},
		{"populated map", api.CapabilitySet{"selinux": true}, true},
		{"empty slice", []api.ValidatorPreview{}, false},
		{"nil slice", []api.ValidatorPreview(nil), false},
		{"populated slice", []api.ValidatorPreview{{}}, true},
		{"empty string", "", false},
		{"non-empty string", "host-1", true},
		{"false bool", false, false},
		{"true bool", true, true},
		{"zero duration", time.Duration(0), false},
		{"non-zero duration", 2 * time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPopulated(reflect.ValueOf(tc.v)); got != tc.want {
				t.Errorf("isPopulated(%#v) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}
}
