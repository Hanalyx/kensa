package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanalyx/kensa-go/internal/agent/wirev1"
)

// TestRunEcho_HappyPath locks AC-05: the echo loop reads one
// frame, mirrors the Request payload into a Response with the
// same correlation_id, writes the Response frame, then exits 0
// when stdin closes.
//
// @spec agent-stdio-subcommand
// @ac AC-05
func TestRunEcho_HappyPath(t *testing.T) {
	// Build a Request frame.
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 12345,
		Payload:       []byte("hello, agent"),
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal Request: %v", err)
	}

	var stdin bytes.Buffer
	if err := Write(&stdin, reqBytes); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	// stdin is now: [4-byte length][N-byte payload], followed
	// by EOF — the echo loop reads one frame, echoes, then
	// gets EOF on the next iteration and returns nil.

	var stdout, stderr bytes.Buffer
	err = Run(context.Background(), &stdin, &stdout, &stderr, HandleEcho)
	if err != nil {
		t.Fatalf("RunEcho: %v; stderr=%s", err, stderr.String())
	}

	// Read the echoed Response frame from stdout.
	respBytes, err := Read(&stdout)
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	var resp wirev1.Response
	if err := proto.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal Response: %v", err)
	}
	if resp.GetSchemaVersion() != 1 {
		t.Errorf("schema_version = %d, want 1", resp.GetSchemaVersion())
	}
	if resp.GetCorrelationId() != req.GetCorrelationId() {
		t.Errorf("correlation_id = %d, want %d (must match Request)",
			resp.GetCorrelationId(), req.GetCorrelationId())
	}
	if !bytes.Equal(resp.GetPayload(), req.GetPayload()) {
		t.Errorf("payload mismatch: got %q, want %q",
			resp.GetPayload(), req.GetPayload())
	}
	if resp.GetError() != nil {
		t.Errorf("Response.error should be nil on echo path; got: %v", resp.GetError())
	}
}

// TestRunEcho_MultipleFrames locks that the echo loop handles
// more than one frame per session — a controller that wants to
// send N requests gets N responses, in order. Critical for L-009
// which builds the real dispatcher on this loop.
func TestRunEcho_MultipleFrames(t *testing.T) {
	var stdin bytes.Buffer
	for i := uint64(1); i <= 5; i++ {
		req := &wirev1.Request{
			SchemaVersion: 1,
			CorrelationId: i,
			Payload:       []byte{byte(i)},
		}
		reqBytes, _ := proto.Marshal(req)
		if err := Write(&stdin, reqBytes); err != nil {
			t.Fatalf("Write frame %d: %v", i, err)
		}
	}

	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), &stdin, &stdout, &stderr, HandleEcho)
	if err != nil {
		t.Fatalf("RunEcho: %v; stderr=%s", err, stderr.String())
	}

	// Drain 5 frames from stdout in order.
	for i := uint64(1); i <= 5; i++ {
		respBytes, err := Read(&stdout)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		var resp wirev1.Response
		if err := proto.Unmarshal(respBytes, &resp); err != nil {
			t.Fatalf("unmarshal frame %d: %v", i, err)
		}
		if resp.GetCorrelationId() != i {
			t.Errorf("frame %d: correlation_id = %d, want %d", i, resp.GetCorrelationId(), i)
		}
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout should be drained; %d bytes remain", stdout.Len())
	}
}

// TestRunEcho_EOFOnEmptyStdin locks that an immediately-closed
// stdin (no frames) returns nil cleanly. This is the
// graceful-shutdown path: SSH client closed without sending
// anything.
func TestRunEcho_EOFOnEmptyStdin(t *testing.T) {
	var stdin, stdout, stderr bytes.Buffer
	err := Run(context.Background(), &stdin, &stdout, &stderr, HandleEcho)
	if err != nil {
		t.Errorf("empty stdin should return nil, got: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("no input → no output; got %d bytes", stdout.Len())
	}
}

// TestRunEcho_TruncatedFrameIsError locks that a peer sending
// half a frame (length prefix promised N bytes but only N/2
// arrived before EOF) terminates the loop with an error. The
// agent surfaces this to operators via stderr; the controller
// will see exit code 1.
func TestRunEcho_TruncatedFrameIsError(t *testing.T) {
	// Length prefix claims 100 bytes, body is empty.
	stdin := bytes.NewBuffer([]byte{0x00, 0x00, 0x00, 0x64})

	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), stdin, &stdout, &stderr, HandleEcho)
	if err == nil {
		t.Error("truncated frame should be an error; got nil")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("error should be io.ErrUnexpectedEOF; got: %v", err)
	}
	if stderr.Len() == 0 {
		t.Error("stderr should carry a diagnostic; got empty")
	}
}

// TestRunEcho_MalformedProtoIsError locks the unmarshal-error
// path. A peer sending a frame whose payload isn't a valid
// wirev1.Request triggers a protobuf decode error, the loop
// terminates.
func TestRunEcho_MalformedProtoIsError(t *testing.T) {
	var stdin bytes.Buffer
	// 4-byte length prefix promising 10 bytes, followed by 10
	// bytes of garbage that can't be a valid Request.
	if err := Write(&stdin, []byte("not a Request")); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), &stdin, &stdout, &stderr, HandleEcho)
	if err == nil {
		t.Error("malformed proto should be an error; got nil")
	}
	// Stderr should carry an "unmarshal Request" diagnostic so
	// an SRE debugging a stuck transport can identify the side
	// (peer sent garbage, not local stream corruption).
	if stderr.Len() == 0 {
		t.Error("stderr should carry a diagnostic; got empty")
	}
}

// TestRunEcho_PreCancelledContext locks AC-06: when ctx is
// already cancelled by the time RunEcho enters its loop, the
// between-frames ctx check fires immediately and the loop
// returns ctx.Err() without attempting a Read.
//
// The mid-read preemption case (controller cancels while stdin
// is blocked) is NOT in L-008's scope — that's L-012's explicit
// shutdown-message type. Adding goroutine-based preemption here
// would leak the read goroutine until stdin closes. For SIGTERM/
// SIGINT today, the OS also closes stdin, so Read returns EOF
// and the loop exits cleanly without needing preemption.
//
// @spec agent-stdio-subcommand
// @ac AC-06
func TestRunEcho_PreCancelledContext(t *testing.T) {
	// Pre-load stdin with frames the loop will NEVER reach —
	// the pre-cancelled ctx must short-circuit before any Read.
	var stdin bytes.Buffer
	req := &wirev1.Request{SchemaVersion: 1, CorrelationId: 1, Payload: []byte("x")}
	reqBytes, _ := proto.Marshal(req)
	_ = Write(&stdin, reqBytes)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE RunEcho is called

	var stdout, stderr bytes.Buffer
	start := time.Now()
	err := Run(ctx, &stdin, &stdout, &stderr, HandleEcho)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("pre-cancelled ctx should return context.Canceled, got: %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("pre-cancelled ctx should return immediately (within 100ms); took %v", elapsed)
	}
	if stdout.Len() != 0 {
		t.Errorf("no frame should be echoed when ctx is pre-cancelled; got %d bytes in stdout", stdout.Len())
	}
}
