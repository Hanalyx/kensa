package mechanism

import (
	"reflect"
	"testing"
)

func TestValidateParams_Conforms(t *testing.T) {
	// schema-correct config_set params conform.
	if got := ValidateParams("config_set", []string{"path", "key", "value", "separator"}); len(got) != 0 {
		t.Errorf("expected conforming, got %v", got)
	}
	// file_permissions one-of: single path conforms.
	if got := ValidateParams("file_permissions", []string{"path", "mode"}); len(got) != 0 {
		t.Errorf("path form should conform, got %v", got)
	}
	// file_permissions one-of: find form conforms.
	if got := ValidateParams("file_permissions", []string{"find_paths", "find_type", "find_args"}); len(got) != 0 {
		t.Errorf("find form should conform, got %v", got)
	}
}

func TestValidateParams_MissingRequired(t *testing.T) {
	got := ValidateParams("config_set", []string{"key", "value"}) // no path
	want := []string{"missing required param 'path'"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestValidateParams_UnknownParam(t *testing.T) {
	// the historical straggler: sysctl rule using 'file' instead of 'persist_file'.
	got := ValidateParams("sysctl_set", []string{"key", "value", "file"})
	want := []string{"unknown param(s) 'file'"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestValidateParams_OneOfMissing(t *testing.T) {
	got := ValidateParams("file_permissions", []string{"mode", "owner"}) // neither path nor find_paths
	want := []string{"requires one of 'path', 'find_paths'"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestValidateParams_UnknownMechanism(t *testing.T) {
	got := ValidateParams("does_not_exist", []string{"x"})
	if len(got) != 1 || got[0] != "unknown mechanism 'does_not_exist'" {
		t.Errorf("got %v", got)
	}
}

// TestHandlerDivergenceMechanismsAreKnown guards the debt ledger: every
// mechanism listed as diverging must be a real, contracted mechanism.
func TestHandlerDivergenceMechanismsAreKnown(t *testing.T) {
	for mech := range HandlerParamDivergence {
		if !Known(mech) {
			t.Errorf("HandlerParamDivergence lists unknown mechanism %q", mech)
		}
	}
}
