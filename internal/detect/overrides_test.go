// Tests for KnownCapabilities and ApplyOverrides (C-028).
package detect

import (
	"reflect"
	"sort"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

func TestKnownCapabilities_NonEmpty(t *testing.T) {
	got := KnownCapabilities()
	if len(got) == 0 {
		t.Fatal("KnownCapabilities returned empty list")
	}
}

func TestKnownCapabilities_Sorted(t *testing.T) {
	got := KnownCapabilities()
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(got, sorted) {
		t.Errorf("KnownCapabilities not sorted alphabetically;\n got: %v\nwant: %v", got, sorted)
	}
}

func TestKnownCapabilities_NoDuplicates(t *testing.T) {
	got := KnownCapabilities()
	seen := make(map[string]bool)
	for _, n := range got {
		if seen[n] {
			t.Errorf("duplicate capability name: %q", n)
		}
		seen[n] = true
	}
}

func TestApplyOverrides_NilOverrides(t *testing.T) {
	detected := api.CapabilitySet{"a": true, "b": false}
	got := ApplyOverrides(detected, nil)
	if !reflect.DeepEqual(got, detected) {
		t.Errorf("nil overrides should return detected unchanged; got %v want %v", got, detected)
	}
}

func TestApplyOverrides_EmptyOverrides(t *testing.T) {
	detected := api.CapabilitySet{"a": true, "b": false}
	got := ApplyOverrides(detected, api.CapabilitySet{})
	if !reflect.DeepEqual(got, detected) {
		t.Errorf("empty overrides should return detected unchanged; got %v want %v", got, detected)
	}
}

func TestApplyOverrides_OverwritesExisting(t *testing.T) {
	detected := api.CapabilitySet{"a": true, "b": false}
	overrides := api.CapabilitySet{"a": false}
	got := ApplyOverrides(detected, overrides)
	want := api.CapabilitySet{"a": false, "b": false}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("override 'a' should flip to false; got %v want %v", got, want)
	}
}

func TestApplyOverrides_AddsNewKeys(t *testing.T) {
	detected := api.CapabilitySet{"a": true}
	overrides := api.CapabilitySet{"c": true}
	got := ApplyOverrides(detected, overrides)
	want := api.CapabilitySet{"a": true, "c": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("override should add new key 'c'; got %v want %v", got, want)
	}
}

func TestApplyOverrides_DoesNotMutateInputs(t *testing.T) {
	detected := api.CapabilitySet{"a": true}
	overrides := api.CapabilitySet{"a": false}
	detectedSnapshot := api.CapabilitySet{"a": true}
	overridesSnapshot := api.CapabilitySet{"a": false}
	_ = ApplyOverrides(detected, overrides)
	if !reflect.DeepEqual(detected, detectedSnapshot) {
		t.Errorf("ApplyOverrides mutated detected: %v != %v", detected, detectedSnapshot)
	}
	if !reflect.DeepEqual(overrides, overridesSnapshot) {
		t.Errorf("ApplyOverrides mutated overrides: %v != %v", overrides, overridesSnapshot)
	}
}
