package footprint

import "testing"

// Unrestorable returns the captured paths flagged immutable by the injected
// check, sorted; empty when none are.
//
// @spec footprint-funnel
// @ac AC-05
func TestUnrestorable(t *testing.T) {
	t.Run("footprint-funnel/AC-05", func(t *testing.T) {})
	captured := New()
	captured.Add(Entry{Path: "/etc/normal", Op: OpModify})
	captured.Add(Entry{Path: "/etc/locked", Op: OpModify})
	captured.Add(Entry{Path: "/etc/also-locked", Op: OpModify})

	immutable := map[string]bool{"/etc/locked": true, "/etc/also-locked": true}
	check := func(p string) (bool, error) { return immutable[p], nil }

	bad := Unrestorable(captured, check)
	if len(bad) != 2 || bad[0] != "/etc/also-locked" || bad[1] != "/etc/locked" {
		t.Errorf("Unrestorable = %v, want [/etc/also-locked /etc/locked] sorted", bad)
	}

	// None immutable → empty.
	if got := Unrestorable(captured, func(string) (bool, error) { return false, nil }); len(got) != 0 {
		t.Errorf("expected none unrestorable, got %v", got)
	}
}

// A check that errors does not turn a transient probe failure into a refusal.
//
// @spec footprint-funnel
// @ac AC-05
func TestUnrestorable_ProbeErrorIsNotARefusal(t *testing.T) {
	t.Run("footprint-funnel/AC-05", func(t *testing.T) {})
	captured := New()
	captured.Add(Entry{Path: "/etc/x", Op: OpModify})
	check := func(string) (bool, error) { return false, errProbe }
	if got := Unrestorable(captured, check); len(got) != 0 {
		t.Errorf("a probe error must not be a refusal; got %v", got)
	}
}

var errProbe = &probeErr{}

type probeErr struct{}

func (*probeErr) Error() string { return "probe failed" }
