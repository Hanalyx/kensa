package rule

import (
	"errors"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// Verifies the fix for the ungated gdm rules: they must SKIP where GDM is absent
// and still RUN where it is present. A gate that skips everywhere would be worse
// than the false pass it replaced.
func TestGdmGateSelectsBothWays(t *testing.T) {
	for _, f := range []string{
		"../../rules/system/gdm-graphical-banner.yml",
		"../../rules/system/gdm-no-autologin.yml",
		"../../rules/system/gdm-session-lock.yml", // control: already correct
	} {
		r, err := ParseFile(f)
		if err != nil {
			t.Fatalf("%s: parse: %v", f, err)
		}
		if _, err := Select(r, api.CapabilitySet{"gdm": true}); err != nil {
			t.Errorf("%s: with gdm capability, expected an implementation, got %v", r.ID, err)
		} else {
			t.Logf("%-24s with gdm    -> RUNS", r.ID)
		}
		_, err = Select(r, api.CapabilitySet{})
		if !errors.Is(err, ErrNoImplementation) {
			t.Errorf("%s: without gdm, expected ErrNoImplementation, got %v", r.ID, err)
		} else {
			t.Logf("%-24s without gdm -> SKIPPED", r.ID)
		}
	}
}
