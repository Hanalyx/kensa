// Protocol version constants. L-012 deliverable per spec
// agent-version-handshake.
//
// Distinct from `schema_version` (uint32=1 today, locked by
// ValidateSchemaVersion at L-007). schema_version controls
// per-message field-level evolution; the Major/Minor
// constants below control the BIG-PICTURE protocol identity.
//
// **Bumping major.** Incompatible-by-design changes:
//   - Removing a message type
//   - Reinterpreting an existing field's semantics
//   - Changing the framing format (L-010's type-byte
//     discriminator)
// Major bumps require explicit founder ratification.
//
// **Bumping minor.** Additive changes:
//   - Adding a new payload variant (e.g., new handler type)
//   - Adding a new optional field on an existing message
//   - Reserving previously-unused field numbers
//
// Across a minor bump, controller-and-agent SHOULD interoperate
// (newer side ignores fields the older side doesn't know
// about). Compatible() returns warnIfMinorDiff=true when the
// peers' minors differ so caller can log a one-line warning.

package wirev1

// ProtocolMajor is the major version of the agent wire
// protocol this build speaks. Bumping is the explicit
// breaking-change gate.
const ProtocolMajor uint32 = 1

// ProtocolMinor is the minor version. Bumping is additive.
const ProtocolMinor uint32 = 0

// ProtocolBuild is a human-readable build identifier for
// the handshake exchange. Operators see this in
// HandshakeAck.build when the agent disagrees with the
// controller's version.
const ProtocolBuild = "v1.0.0-l012"

// Compatible reports whether a remote endpoint speaking
// (remoteMajor, remoteMinor) is compatible with this build.
// Returns:
//   - (true, false)  exact match
//   - (true, true)   same major, different minor — accepted
//                    with a warning the caller should log
//   - (false, false) major mismatch — incompatible
func Compatible(remoteMajor, remoteMinor uint32) (compat bool, warnIfMinorDiff bool) {
	if remoteMajor != ProtocolMajor {
		return false, false
	}
	if remoteMinor != ProtocolMinor {
		return true, true
	}
	return true, false
}
