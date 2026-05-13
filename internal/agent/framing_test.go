package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestFraming_Roundtrip locks AC-01: Write/Read round-trip
// the payload byte-for-byte AND preserves the FrameType for
// representative sizes.
//
// @spec agent-framing-production
// @ac AC-01
func TestFraming_Roundtrip(t *testing.T) {
	t.Log("// @spec agent-framing-production")
	t.Log("// @ac AC-01")
	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"kibibyte", 1024},
		{"mebibyte", 1024 * 1024},
		// 16 MiB - 1 verifies the upper bound without an
		// allocation that could OOM a constrained CI runner.
		{"near_cap", int(DefaultMaxMessageBytes) - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.size)
			for i := range payload {
				payload[i] = byte(i % 251)
			}
			var buf bytes.Buffer
			if err := Write(&buf, FramePayload, payload, nil); err != nil {
				t.Fatalf("Write: %v", err)
			}
			gotType, got, err := Read(&buf, nil)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if gotType != FramePayload {
				t.Errorf("frame type: got 0x%02x, want 0x%02x", byte(gotType), byte(FramePayload))
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("roundtrip mismatch: payloads differ (size=%d)", tc.size)
			}
		})
	}
}

// TestFraming_RejectsUnknownType locks AC-02: type byte values
// other than FramePayload (0x01) are rejected with
// ErrUnknownFrameType. The encoder applies the same check.
//
// @spec agent-framing-production
// @ac AC-02
func TestFraming_RejectsUnknownType(t *testing.T) {
	t.Log("// @spec agent-framing-production")
	t.Log("// @ac AC-02")
	t.Run("decode_unknown_type", func(t *testing.T) {
		// Manually construct a frame with type 0x02 (reserved
		// for L-012+ but not recognized at L-010).
		var buf bytes.Buffer
		buf.WriteByte(0x02)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], 0)
		buf.Write(lenBuf[:])
		_, _, err := Read(&buf, nil)
		if err == nil {
			t.Fatal("expected ErrUnknownFrameType, got nil")
		}
		if !errors.Is(err, ErrUnknownFrameType) {
			t.Errorf("err should be ErrUnknownFrameType; got: %v", err)
		}
	})
	t.Run("encode_unknown_type", func(t *testing.T) {
		var buf bytes.Buffer
		err := Write(&buf, FrameType(0xFE), []byte("x"), nil)
		if err == nil {
			t.Fatal("expected ErrUnknownFrameType on encode, got nil")
		}
		if !errors.Is(err, ErrUnknownFrameType) {
			t.Errorf("err should be ErrUnknownFrameType; got: %v", err)
		}
	})
}

// TestFraming_ConfigurableMaxSize locks AC-03: FramingOptions
// .MaxMessageBytes override applies on both encode and decode.
// 0 falls back to the 16 MiB default.
//
// @spec agent-framing-production
// @ac AC-03
func TestFraming_ConfigurableMaxSize(t *testing.T) {
	t.Log("// @spec agent-framing-production")
	t.Log("// @ac AC-03")
	t.Run("decode_respects_override", func(t *testing.T) {
		opts := &FramingOptions{MaxMessageBytes: 100}
		// Forge a frame claiming length=101.
		var buf bytes.Buffer
		buf.WriteByte(byte(FramePayload))
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], 101)
		buf.Write(lenBuf[:])

		_, _, err := Read(&buf, opts)
		if err == nil {
			t.Fatal("expected ErrFrameTooLarge, got nil")
		}
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Errorf("err should be ErrFrameTooLarge; got: %v", err)
		}
	})
	t.Run("encode_respects_override", func(t *testing.T) {
		opts := &FramingOptions{MaxMessageBytes: 10}
		var buf bytes.Buffer
		err := Write(&buf, FramePayload, make([]byte, 11), opts)
		if err == nil {
			t.Fatal("expected ErrFrameTooLarge on encode, got nil")
		}
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Errorf("err should be ErrFrameTooLarge; got: %v", err)
		}
	})
	t.Run("zero_falls_back_to_default", func(t *testing.T) {
		opts := &FramingOptions{MaxMessageBytes: 0}
		var buf bytes.Buffer
		// 1 byte payload under the default cap should encode/
		// decode cleanly.
		if err := Write(&buf, FramePayload, []byte("x"), opts); err != nil {
			t.Fatalf("Write with zero opts: %v", err)
		}
		_, got, err := Read(&buf, opts)
		if err != nil {
			t.Fatalf("Read with zero opts: %v", err)
		}
		if string(got) != "x" {
			t.Errorf("roundtrip: got %q, want %q", got, "x")
		}
	})
}

// TestFraming_RejectsOversizedFrame locks the security guard:
// the default 16 MiB cap rejects a peer's oversize length
// prefix BEFORE allocation. Without this, a 4 GiB length would
// force make([]byte, 4 GB) and OOM the agent.
func TestFraming_RejectsOversizedFrame(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(byte(FramePayload))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], DefaultMaxMessageBytes+1)
	buf.Write(lenBuf[:])

	_, _, err := Read(&buf, nil)
	if err == nil {
		t.Fatal("expected ErrFrameTooLarge, got nil")
	}
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("err should be ErrFrameTooLarge; got: %v", err)
	}
}

// TestFraming_PartialReads: io.ReadFull semantics for both the
// 5-byte header and the payload. Worst-case 1-byte-per-Read
// fragmentation (SSH transport with small TCP segments).
func TestFraming_PartialReads(t *testing.T) {
	payload := []byte("hello, framed world")

	var buf bytes.Buffer
	if err := Write(&buf, FramePayload, payload, nil); err != nil {
		t.Fatalf("Write: %v", err)
	}
	r := &oneByteReader{src: buf.Bytes()}
	gotType, got, err := Read(r, nil)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if gotType != FramePayload {
		t.Errorf("frame type: got 0x%02x, want 0x%02x", byte(gotType), byte(FramePayload))
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("partial-read roundtrip: got %q, want %q", got, payload)
	}
}

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

// TestFraming_EOFSemantics: clean EOF before any header byte
// returns io.EOF (legitimate stream close); EOF mid-frame
// returns io.ErrUnexpectedEOF.
func TestFraming_EOFSemantics(t *testing.T) {
	t.Run("clean_eof_between_frames", func(t *testing.T) {
		var buf bytes.Buffer
		_, _, err := Read(&buf, nil)
		if !errors.Is(err, io.EOF) {
			t.Errorf("expected io.EOF on empty stream, got: %v", err)
		}
	})

	t.Run("truncated_after_header", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteByte(byte(FramePayload))
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], 100)
		buf.Write(lenBuf[:])
		// Length says 100; stream has 0 payload bytes.
		_, _, err := Read(&buf, nil)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("expected io.ErrUnexpectedEOF, got: %v", err)
		}
	})

	t.Run("truncated_in_header", func(t *testing.T) {
		// Two bytes — partial of the 5-byte header.
		buf := bytes.NewBuffer([]byte{0x01, 0x00})
		_, _, err := Read(buf, nil)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("expected io.ErrUnexpectedEOF on truncated header, got: %v", err)
		}
	})
}

// TestFraming_OversizedErrorMessage locks the error string
// content for the size-rejection case.
func TestFraming_OversizedErrorMessage(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(byte(FramePayload))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], DefaultMaxMessageBytes+1)
	buf.Write(lenBuf[:])

	_, _, err := Read(&buf, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	for _, want := range []string{"cap=", "length="} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got: %v", want, err)
		}
	}
}
