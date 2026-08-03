package servicedbus

import "fmt"

// unitFileStates is the value domain of systemd's UnitFileState property,
// the value captured as prior_enabled.
var unitFileStates = map[string]bool{
	"enabled": true, "enabled-runtime": true, "linked": true,
	"linked-runtime": true, "alias": true, "masked": true,
	"masked-runtime": true, "static": true, "indirect": true,
	"disabled": true, "generated": true, "transient": true, "bad": true,
}

// activeStates is the value domain of systemd's ActiveState property, the
// value captured as prior_active. It shares no member with unitFileStates,
// which is what makes an inverted record detectable.
var activeStates = map[string]bool{
	"active": true, "reloading": true, "inactive": true, "failed": true,
	"activating": true, "deactivating": true, "maintenance": true,
}

// CheckPreStateOrientation reports whether a captured service pre-state has
// its two values transposed.
//
// Releases before the property-name fix read `systemctl show` output
// positionally and stored UnitFileState and ActiveState under each other's
// keys. Those records are still in transaction logs, and rollback cannot
// distinguish them by shape: both fields are non-empty strings. Acting on
// one drives the unit toward a state the host was never in, and the
// resulting RollbackResult reports success.
//
// The two property domains share no member, so a prior_enabled holding an
// ActiveState token while prior_active holds a UnitFileState token is not a
// heuristic: it is a record that cannot have come from a correct capture.
//
// Detection is deliberately narrow. Only the provable transposition is
// reported. A value that is merely unrecognized passes, because systemd
// gains property values over time and refusing to roll back a record from a
// newer systemd would turn a forward-compatibility gap into an outage. The
// goal is to refuse the case we can prove, not to guess.
func CheckPreStateOrientation(priorEnabled, priorActive string) error {
	if activeStates[priorEnabled] && unitFileStates[priorActive] {
		return fmt.Errorf(
			"pre-state is transposed: prior_enabled=%q is an ActiveState and prior_active=%q is a UnitFileState. "+
				"This record was captured by a release that read the two properties in the wrong order, so its values "+
				"do not describe the host. Refusing to act on it: re-run `kensa check` against the host to establish "+
				"the current state",
			priorEnabled, priorActive)
	}
	return nil
}
