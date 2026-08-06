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

// The identity rules must run only where identity actually comes from a
// directory. Both directions matter and for different reasons.
//
// Skipping on a local host is the point: before the gate,
// sssd-service-enabled-active ran everywhere and a measured Ubuntu server with
// local accounts and no SSSD reported FAIL, which reads as a broken host rather
// than an inapplicable rule.
//
// Running on a joined host is what makes the rules worth having. These three are
// the only checks that catch a host which is joined but bypassable: a local
// account beside the directory is invisible from the directory side, because a
// host that stopped asking looks the same as a host nobody is logging into.
func TestDirectoryJoinedGateSelectsBothWays(t *testing.T) {
	for _, f := range []string{
		"../../rules/services/sssd-service-enabled-active.yml",
		"../../rules/access-control/pam-directory-auth-enabled.yml",
		"../../rules/access-control/nsswitch-directory-lookups-complete.yml",
	} {
		r, err := ParseFile(f)
		if err != nil {
			t.Fatalf("%s: parse: %v", f, err)
		}
		if _, err := Select(r, api.CapabilitySet{"directory_joined": true}); err != nil {
			t.Errorf("%s: on a directory-joined host, expected an implementation, got %v", r.ID, err)
		} else {
			t.Logf("%-36s joined -> RUNS", r.ID)
		}
		_, err = Select(r, api.CapabilitySet{})
		if !errors.Is(err, ErrNoImplementation) {
			t.Errorf("%s: on a local-accounts host, expected ErrNoImplementation, got %v", r.ID, err)
		} else {
			t.Logf("%-36s local  -> SKIPPED", r.ID)
		}
	}
}
