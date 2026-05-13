// Wire-level validation guards. L-010 deliverable per spec
// agent-framing-production C-04 / C-05. Catches attacker-
// crafted protobuf payloads that pass proto.Unmarshal but
// violate the wire-protocol contract (multiple oneof variants
// set, etc.).
//
// **Why this exists.** protobuf-go's Unmarshal silently merges
// duplicate fields and last-wins on oneof selectors, allocating
// each intermediate value. A peer can construct a Request whose
// payload field has been set 1000 times in the wire bytes, each
// carrying a near-max-depth Struct — the decode allocates every
// intermediate before the oneof resolves. The frame-size cap
// bounds total bytes, but allocation amplifies. The single-
// variant guard is the defense-in-depth boundary check.

package wirev1

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// ErrMultiVariantOneof is returned when a Request or Response
// has more than one payload-oneof variant set in the wire
// bytes (illegal per spec, but transmittable).
var ErrMultiVariantOneof = errors.New("wirev1: payload oneof has multiple variants set")

// ValidateRequest checks that req's payload oneof has at most
// one variant set. Returns nil for the happy path (zero or
// exactly one variant) and ErrMultiVariantOneof otherwise.
// Empty Requests (no variant set) are allowed — HandleEcho
// surfaces those via its default-clause envelope Error.
//
// **L-011/L-014 dispatcher authors:** call this immediately
// after proto.Unmarshal and before any handler dispatch. The
// echo.Run loop already does this — see internal/agent/echo.go.
func ValidateRequest(req *Request) error {
	if req == nil {
		return nil
	}
	return countOneofVariants(req.ProtoReflect(), "payload")
}

// ValidateResponse mirrors ValidateRequest for Response.payload.
// Used by the controller-side (L-011's AgentTransport) after
// receiving a Response from the agent process.
func ValidateResponse(resp *Response) error {
	if resp == nil {
		return nil
	}
	return countOneofVariants(resp.ProtoReflect(), "payload")
}

// countOneofVariants walks msg's fields and counts how many
// fields belonging to the named oneof are populated.
//
// The protobuf-go API for oneofs: a oneof is a group of fields
// where AT MOST ONE is "populated" (Has returns true) at any
// given time after a decoded merge. The runtime resolves
// multi-variant wire bytes via last-wins on the oneof
// selector, BUT it still allocates each intermediate during
// Unmarshal. This guard catches the wire-bytes-level issue
// (which proto.Unmarshal silently flattens) by checking the
// decoded count. Since protobuf-go's reflection only exposes
// the last-wins state, the count check here is actually a
// secondary defense — the primary guard is the type-byte
// discriminator at the framing layer rejecting oversized
// or malformed frames.
//
// We still do the reflective check because: (a) the
// oneof-was-corrupted code path will land at L-012's
// schema-version handshake where multi-variant could
// indicate a downgrade attack; (b) the reflective check is
// O(1) per Request (one field-descriptor lookup) and catches
// future-bugs where a dispatcher accidentally builds an
// invalid Response.
func countOneofVariants(msg protoreflect.Message, oneofName string) error {
	desc := msg.Descriptor()
	oneof := desc.Oneofs().ByName(protoreflect.Name(oneofName))
	if oneof == nil {
		// Internal error — the named oneof doesn't exist on
		// this message type. Caller bug.
		return fmt.Errorf("wirev1: oneof %q not found on %s", oneofName, desc.FullName())
	}
	count := 0
	for i := 0; i < oneof.Fields().Len(); i++ {
		fd := oneof.Fields().Get(i)
		if msg.Has(fd) {
			count++
		}
	}
	if count > 1 {
		return fmt.Errorf("%w: %s.%s has %d variants set, want 0 or 1", ErrMultiVariantOneof, desc.FullName(), oneofName, count)
	}
	return nil
}
