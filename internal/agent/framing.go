// Production length-prefix framing for the kensa agent stdin/
// stdout transport. L-010 deliverable per spec
// agent-framing-production. Supersedes the L-008 stub framing
// (the API was always advertised as INTERNAL; no external
// caller exists outside this repo).
//
// **Wire format v2:**
//
//	+--------+--------+-------------------+
//	| type   | length | payload           |
//	| u8     | u32-BE | N bytes (proto)   |
//	+--------+--------+-------------------+
//
// The 1-byte type discriminator precedes the 4-byte big-endian
// length, then the N-byte protobuf payload. Type byte values:
//
//	0x01 FramePayload   wirev1.Request or wirev1.Response
//	0x02..0xFF          RESERVED — decoder rejects with error
//
// Future frame types (L-012+):
//   - Out-of-band heartbeat (low-latency liveness on a separate
//     channel from payload, so a slow Apply doesn't delay a
//     heartbeat ack)
//   - Control frames (compressed payload, shutdown
//     negotiation)
//   - Etc.
//
// Adding a new frame type is an additive change: define a new
// FrameType constant; the decoder dispatches on type and
// rejects unknown values; old agents reject new types
// cleanly, new agents recognize them.
//
// **Why io.ReadFull.** SSH stdin/stdout is a stream of bytes;
// nothing guarantees a single Read() returns a complete frame.
// io.ReadFull (used for both header and payload) handles
// fragmentation correctly.

package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

// FrameType is the 1-byte discriminator at the start of every
// frame on the agent wire.
//
// **Zero value (FrameInvalid) is intentionally invalid** so a
// caller doing `var t FrameType; Write(w, t, payload, opts)`
// gets a loud `ErrUnknownFrameType` rather than a silent
// fallback. Always use a named constant.
type FrameType byte

// Frame type discriminator values. Extending the wire format
// with a new type (e.g., L-012's FrameHeartbeat, L-013's
// FrameBinaryChunk) requires THREE additive steps:
//
//  1. Add the new constant below.
//  2. Add it to `knownFrameTypes` (the set below).
//  3. Update any handler-loop dispatch that needs to route
//     the new type (e.g., echo.go's Run() may need to ignore
//     heartbeats and let a separate goroutine handle them).
//
// No edits to Read or Write function bodies are required —
// the type-byte check goes through `knownFrameTypes`, not a
// hardcoded conditional. This is the L-010 extensibility
// contract.
const (
	FrameInvalid FrameType = 0x00 // zero value; explicitly reserved/rejected
	FramePayload FrameType = 0x01
)

// knownFrameTypes is the membership set the codec consults to
// decide whether to accept a type-byte value. Reserved values
// (0x02..0xFF today) are NOT in this set and are rejected with
// ErrUnknownFrameType. L-012 / L-013 extend this set with their
// new types as additive changes.
var knownFrameTypes = map[FrameType]bool{
	FramePayload: true,
}

// isKnown reports whether t is a recognized frame type. False
// for FrameInvalid (0x00) and all reserved values.
func isKnown(t FrameType) bool {
	return knownFrameTypes[t]
}

// knownTypeNames returns a slice of "0xNN" strings for every
// type in knownFrameTypes, sorted. Used in error messages so a
// peer sending an unknown type sees the actual list this build
// supports (instead of a hardcoded-and-rotting "L-010 says
// only 0x01" message).
func knownTypeNames() []string {
	out := make([]string, 0, len(knownFrameTypes))
	for t := range knownFrameTypes {
		out = append(out, fmt.Sprintf("0x%02x", byte(t)))
	}
	sort.Strings(out)
	return out
}

// DefaultMaxMessageBytes is the default cap on a single frame
// (header + payload). 16 MiB matches the L-008 stub policy so
// L-008 → L-010 doesn't change the visible memory bound for
// operators.
const DefaultMaxMessageBytes uint32 = 16 * 1024 * 1024

// FramingOptions configures encoder/decoder limits. Pass nil
// for defaults. Adding a new optional field is non-breaking
// (zero-valued fields fall back to defaults).
type FramingOptions struct {
	// MaxMessageBytes overrides DefaultMaxMessageBytes for
	// the size cap. 0 means "use default." The cap is applied
	// to both incoming (decoder rejects oversize frames before
	// allocating) and outgoing (encoder refuses to write
	// oversize payloads).
	MaxMessageBytes uint32
}

// ErrFrameTooLarge is returned when a peer's length prefix
// exceeds the configured (or default) max-message-bytes cap.
// The decoder refuses to allocate before the length is
// bounds-checked.
var ErrFrameTooLarge = errors.New("agent: frame exceeds max-message-bytes cap")

// ErrUnknownFrameType is returned when the type byte at the
// start of a frame is not a recognized FrameType. The decoder
// does NOT advance past the unknown frame — the stream is
// likely corrupted at this point and the caller should treat
// this as a fatal protocol error.
var ErrUnknownFrameType = errors.New("agent: unknown frame type")

// resolveMaxBytes returns opts.MaxMessageBytes when opts is
// non-nil and the field is non-zero; DefaultMaxMessageBytes
// otherwise.
func resolveMaxBytes(opts *FramingOptions) uint32 {
	if opts != nil && opts.MaxMessageBytes > 0 {
		return opts.MaxMessageBytes
	}
	return DefaultMaxMessageBytes
}

// Read reads one length-prefixed typed frame from r. Returns
// the frame type, the payload bytes (without header), and an
// error.
//
// Returns io.EOF when r returns EOF cleanly BEFORE the next
// type byte — peer closed the stream between frames; legitimate
// shutdown. Returns io.ErrUnexpectedEOF if EOF arrives MID-FRAME
// (after type byte read, during length or payload), indicating
// corruption or truncation.
//
// Returns ErrFrameTooLarge if the length prefix exceeds the
// configured cap. Returns ErrUnknownFrameType if the type byte
// is not a recognized FrameType value.
func Read(r io.Reader, opts *FramingOptions) (FrameType, []byte, error) {
	// Header: 1 byte type + 4 bytes length. Read both with one
	// io.ReadFull so a partial read between type and length
	// is handled correctly.
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}

	frameType := FrameType(header[0])
	if !isKnown(frameType) {
		return frameType, nil, fmt.Errorf("%w: 0x%02x (known types: %v)", ErrUnknownFrameType, byte(frameType), knownTypeNames())
	}

	n := binary.BigEndian.Uint32(header[1:5])
	maxBytes := resolveMaxBytes(opts)
	if n > maxBytes {
		return frameType, nil, fmt.Errorf("%w: peer sent length=%d, cap=%d", ErrFrameTooLarge, n, maxBytes)
	}

	// Empty payload (n==0) is legal — peer can send a
	// zero-byte PAYLOAD frame as a keepalive. make([]byte, 0)
	// is fine.
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		// Any error mid-payload is unexpected: we committed
		// to N bytes when we read the length prefix.
		if errors.Is(err, io.EOF) {
			return frameType, nil, io.ErrUnexpectedEOF
		}
		return frameType, nil, err
	}
	return frameType, payload, nil
}

// Write encodes a single typed frame onto w: 1-byte type, 4-byte
// big-endian length, payload. Refuses to write a payload larger
// than the configured cap. Refuses to write an unknown frame
// type (the symmetric check to Read's ErrUnknownFrameType).
func Write(w io.Writer, t FrameType, payload []byte, opts *FramingOptions) error {
	if !isKnown(t) {
		return fmt.Errorf("%w: 0x%02x (known types: %v)", ErrUnknownFrameType, byte(t), knownTypeNames())
	}
	maxBytes := resolveMaxBytes(opts)
	if uint32(len(payload)) > maxBytes {
		return fmt.Errorf("%w: tried to write %d bytes, cap=%d", ErrFrameTooLarge, len(payload), maxBytes)
	}
	var header [5]byte
	header[0] = byte(t)
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("agent: write frame header to peer: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("agent: write frame payload to peer: %w", err)
	}
	return nil
}
