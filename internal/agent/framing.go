// Stub length-prefix framing for the kensa agent stdin/stdout
// transport. L-008 deliverable per spec agent-stdio-subcommand.
//
// **Wire format (STUB — not stable across kensa versions).**
//
//	+--------+-------------------+
//	| 4-byte | N bytes           |
//	| big-EU | protobuf payload  |
//	+--------+-------------------+
//
// The 4-byte big-endian unsigned length prefix precedes a
// payload of exactly N bytes (typically a marshalled
// wirev1.Request or wirev1.Response).
//
// **This format is INTERNAL.** L-010 supersedes it with the
// production framing contract (frame-type discriminator byte for
// heartbeat channel demux, configurable max-size policy,
// partial-read recovery semantics). Do NOT ship code that depends
// on the L-008 stub bit-pattern across kensa releases.
//
// **L-010 migration plan (recorded here for the future author).**
// Extend Read/Write IN PLACE rather than introducing a
// internal/agent/framing/v2/ package — at L-008 the only callers
// are internal/agent/echo.go (this file's package) and the
// kensa agent E2E test, both updated in the same commit that
// extends the format. No external callers exist as of L-008, so
// in-place extension carries no migration cost.
//
// **Why io.ReadFull.** SSH stdin/stdout is a stream of bytes;
// nothing guarantees that a single Read() call returns the full
// frame. We use io.ReadFull so a peer writing a 1 MiB frame in 64
// KiB chunks still decodes correctly.

package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxMessageBytes caps the length prefix the decoder will trust.
// A peer sending length=4 GiB without this cap forces
// make([]byte, 4 GB) and OOMs the agent process. 16 MiB matches
// L-010's planned policy so L-008 → L-010 doesn't change the
// memory bound visible to operators.
const MaxMessageBytes = 16 * 1024 * 1024

// ErrFrameTooLarge is returned when a peer's length prefix
// exceeds MaxMessageBytes. The decoder refuses to allocate before
// the length is bounds-checked.
var ErrFrameTooLarge = errors.New("agent: frame exceeds MaxMessageBytes")

// Read reads one length-prefixed frame from r. Returns the
// payload bytes (without the prefix). Returns io.EOF when r
// returns EOF cleanly BEFORE the next length prefix —
// indicating the peer closed the stream between frames, which is
// a legitimate clean shutdown. Returns io.ErrUnexpectedEOF if
// EOF arrives MID-FRAME (after length prefix, during payload),
// indicating a corrupted / truncated message.
func Read(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	// Use the underlying io.ReadFull error contract: returns
	// io.EOF iff no bytes were read AT ALL before EOF. If we got
	// some-but-not-all of the length prefix, that's an
	// unexpected truncation, and io.ReadFull turns it into
	// io.ErrUnexpectedEOF. This is exactly the EOF semantics
	// C-06 requires.
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > MaxMessageBytes {
		return nil, fmt.Errorf("%w: peer sent length=%d, cap=%d", ErrFrameTooLarge, n, MaxMessageBytes)
	}
	// Empty payload (n==0) is legal — peer can send a
	// zero-byte frame as a keepalive. make([]byte, 0) is fine.
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		// Any error mid-payload is unexpected: we committed to N
		// bytes when we read the length prefix.
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return payload, nil
}

// Write encodes a single frame onto w: 4-byte big-endian length
// prefix followed by payload. Refuses to write a payload larger
// than MaxMessageBytes — the encoder respects the same bound the
// decoder enforces, so we can't accidentally emit messages our
// own decoder would reject on the round-trip.
func Write(w io.Writer, payload []byte) error {
	if len(payload) > MaxMessageBytes {
		return fmt.Errorf("%w: tried to write %d bytes, cap=%d", ErrFrameTooLarge, len(payload), MaxMessageBytes)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("agent: write length prefix to peer: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("agent: write payload to peer: %w", err)
	}
	return nil
}
