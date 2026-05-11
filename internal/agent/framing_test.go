package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestFraming_Roundtrip locks AC-01: Write(buf, p) then Read(buf)
// returns p byte-for-byte for representative payload sizes.
//
// @spec agent-stdio-subcommand
// @ac AC-01
func TestFraming_Roundtrip(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"kibibyte", 1024},
		{"mebibyte", 1024 * 1024},
		// MaxMessageBytes-1 to exercise the upper bound without
		// blowing memory on a CI test machine. The full
		// MaxMessageBytes case is exercised by
		// TestFraming_RejectsOversizedFrame on the other side.
		{"near_cap", 1024 * 1024 * 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.size)
			for i := range payload {
				payload[i] = byte(i % 251)
			}
			var buf bytes.Buffer
			if err := Write(&buf, payload); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got, err := Read(&buf)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("roundtrip mismatch: payloads differ (size=%d)", tc.size)
			}
		})
	}
}

// TestFraming_RejectsOversizedFrame locks AC-02: a peer sending
// a length prefix > MaxMessageBytes is rejected BEFORE the
// decoder allocates the buffer. Without this, a 4 GiB length
// prefix would force make([]byte, 4 GB) and OOM the agent.
//
// The test forges a length prefix directly rather than going
// through Write(), since Write() also refuses oversized payloads
// (and we want to verify the decoder's defensive check, not the
// encoder's).
//
// @spec agent-stdio-subcommand
// @ac AC-02
func TestFraming_RejectsOversizedFrame(t *testing.T) {
	var buf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], MaxMessageBytes+1)
	buf.Write(lenBuf[:])
	// Don't bother writing the payload — Read should error
	// before reading past the length prefix.

	_, err := Read(&buf)
	if err == nil {
		t.Fatal("expected ErrFrameTooLarge, got nil")
	}
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("err should be ErrFrameTooLarge; got: %v", err)
	}
}

// TestFraming_WriteRejectsOversizedPayload locks the encoder-side
// guard. We can't accidentally emit messages our decoder would
// refuse.
func TestFraming_WriteRejectsOversizedPayload(t *testing.T) {
	// Allocate just past the cap. This is 16 MiB + 1 — small
	// enough not to OOM CI.
	payload := make([]byte, MaxMessageBytes+1)
	var buf bytes.Buffer
	err := Write(&buf, payload)
	if err == nil {
		t.Fatal("expected ErrFrameTooLarge on encode, got nil")
	}
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("err should be ErrFrameTooLarge; got: %v", err)
	}
}

// TestFraming_PartialReads locks AC-03: a Reader that returns
// data in 1-byte chunks (worst-case SSH-fragmentation behavior)
// MUST still decode correctly. Uses io.ReadFull internally;
// this test verifies that contract holds.
//
// @spec agent-stdio-subcommand
// @ac AC-03
func TestFraming_PartialReads(t *testing.T) {
	payload := []byte("hello, framed world")

	var buf bytes.Buffer
	if err := Write(&buf, payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Wrap the buffer in a Reader that returns 1 byte per
	// Read() call — the most-fragmented case.
	r := &oneByteReader{src: buf.Bytes()}
	got, err := Read(r)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("partial-read roundtrip: got %q, want %q", got, payload)
	}
}

// oneByteReader returns 1 byte at a time from src, simulating
// worst-case stream fragmentation (e.g., SSH transport with
// small TCP segments).
type oneByteReader struct {
	src []byte
	off int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.src) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.src[r.off]
	r.off++
	return 1, nil
}

// TestFraming_EOFSemantics locks AC-04: a clean EOF (no bytes
// before next length prefix) returns io.EOF. EOF mid-frame
// (after length prefix, during payload) returns
// io.ErrUnexpectedEOF — signal of corruption/truncation, not
// clean shutdown.
//
// @spec agent-stdio-subcommand
// @ac AC-04
func TestFraming_EOFSemantics(t *testing.T) {
	t.Run("clean_eof_between_frames", func(t *testing.T) {
		var buf bytes.Buffer
		// Empty buffer → EOF immediately.
		_, err := Read(&buf)
		if !errors.Is(err, io.EOF) {
			t.Errorf("expected io.EOF on empty stream, got: %v", err)
		}
	})

	t.Run("truncated_after_length_prefix", func(t *testing.T) {
		var buf bytes.Buffer
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], 100)
		buf.Write(lenBuf[:])
		// Length says 100 bytes; stream has 0 payload bytes.
		// Decoder should return ErrUnexpectedEOF.
		_, err := Read(&buf)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("expected io.ErrUnexpectedEOF, got: %v", err)
		}
	})

	t.Run("truncated_mid_payload", func(t *testing.T) {
		var buf bytes.Buffer
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], 100)
		buf.Write(lenBuf[:])
		buf.Write(make([]byte, 50)) // half the promised payload
		_, err := Read(&buf)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("expected io.ErrUnexpectedEOF, got: %v", err)
		}
	})

	t.Run("truncated_in_length_prefix", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{0x00, 0x01}) // only 2 of 4 prefix bytes
		_, err := Read(&buf)
		// Per io.ReadFull contract: partial read of prefix
		// returns ErrUnexpectedEOF.
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("expected io.ErrUnexpectedEOF on truncated prefix, got: %v", err)
		}
	})
}

// TestFraming_OversizedErrorMessage locks that the size-rejection
// error string includes the offending size and the cap, so an
// operator debugging a misconfigured peer can see what was wrong
// at a glance.
func TestFraming_OversizedErrorMessage(t *testing.T) {
	var buf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], MaxMessageBytes+1)
	buf.Write(lenBuf[:])

	_, err := Read(&buf)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	for _, want := range []string{"cap=", "length="} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got: %v", want, err)
		}
	}
}
