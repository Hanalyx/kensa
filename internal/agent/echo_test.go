package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanalyx/kensa-go/internal/agent/wirev1"
)

// TestHandleEcho_TypedDispatch locks L-009 AC-04: the echo
// handler switches on the Request's oneof variant and returns a
// Response variant of the matching type. ApplyRequest →
// ApplyResponse, CaptureRequest → CaptureResponse, etc.
//
// @spec agent-wire-handler-schema
// @ac AC-04
func TestHandleEcho_TypedDispatch(t *testing.T) {
	cases := []struct {
		name           string
		req            *wirev1.Request
		assertResponse func(t *testing.T, resp *wirev1.Response)
	}{
		{
			"apply",
			&wirev1.Request{
				SchemaVersion: 1,
				CorrelationId: 1,
				Payload: &wirev1.Request_Apply{
					Apply: &wirev1.ApplyRequest{Mechanism: "file_content"},
				},
			},
			func(t *testing.T, resp *wirev1.Response) {
				if _, ok := resp.GetPayload().(*wirev1.Response_ApplyResp); !ok {
					t.Errorf("ApplyRequest should produce ApplyResponse variant; got %T", resp.GetPayload())
				}
			},
		},
		{
			"capture",
			&wirev1.Request{
				SchemaVersion: 1,
				CorrelationId: 2,
				Payload: &wirev1.Request_Capture{
					Capture: &wirev1.CaptureRequest{Mechanism: "file_permissions"},
				},
			},
			func(t *testing.T, resp *wirev1.Response) {
				if _, ok := resp.GetPayload().(*wirev1.Response_CaptureResp); !ok {
					t.Errorf("CaptureRequest should produce CaptureResponse variant; got %T", resp.GetPayload())
				}
			},
		},
		{
			"rollback",
			&wirev1.Request{
				SchemaVersion: 1,
				CorrelationId: 3,
				Payload: &wirev1.Request_Rollback{
					Rollback: &wirev1.RollbackRequest{PreState: &wirev1.WirePreState{Mechanism: "file_permissions"}},
				},
			},
			func(t *testing.T, resp *wirev1.Response) {
				if _, ok := resp.GetPayload().(*wirev1.Response_RollbackResp); !ok {
					t.Errorf("RollbackRequest should produce RollbackResponse variant; got %T", resp.GetPayload())
				}
			},
		},
		{
			"heartbeat",
			&wirev1.Request{
				SchemaVersion: 1,
				CorrelationId: 4,
				Payload: &wirev1.Request_Heartbeat{
					Heartbeat: &wirev1.HeartbeatRequest{Token: 0xfeedface, SentUnixMicros: 12345},
				},
			},
			func(t *testing.T, resp *wirev1.Response) {
				ack, ok := resp.GetPayload().(*wirev1.Response_HeartbeatAck)
				if !ok {
					t.Errorf("HeartbeatRequest should produce HeartbeatAck variant; got %T", resp.GetPayload())
					return
				}
				if ack.HeartbeatAck.GetToken() != 0xfeedface {
					t.Errorf("token round-trip: got %#x, want 0xfeedface", ack.HeartbeatAck.GetToken())
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleEcho(tc.req)
			tc.assertResponse(t, resp)
		})
	}
}

// TestHandleEcho_PreservesCorrelation locks L-009 AC-05: the
// handler mirrors schema_version + correlation_id from Request
// onto Response. The controller relies on correlation_id to
// match async responses.
//
// @spec agent-wire-handler-schema
// @ac AC-05
func TestHandleEcho_PreservesCorrelation(t *testing.T) {
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 0xdeadbeef,
		Payload: &wirev1.Request_Apply{
			Apply: &wirev1.ApplyRequest{Mechanism: "x"},
		},
	}
	resp := HandleEcho(req)
	if resp.GetSchemaVersion() != 1 {
		t.Errorf("schema_version: got %d, want 1", resp.GetSchemaVersion())
	}
	if resp.GetCorrelationId() != 0xdeadbeef {
		t.Errorf("correlation_id: got %#x, want 0xdeadbeef", resp.GetCorrelationId())
	}
}

// TestHandleEcho_HeartbeatToken locks AC-07: token must round-
// trip exactly (the controller pairs HeartbeatAck with the right
// outstanding ping by token).
//
// @spec agent-wire-handler-schema
// @ac AC-07
func TestHandleEcho_HeartbeatToken(t *testing.T) {
	for _, token := range []uint64{0, 1, 0xffffffff, 0xffffffffffffffff} {
		req := &wirev1.Request{
			SchemaVersion: 1,
			CorrelationId: 1,
			Payload: &wirev1.Request_Heartbeat{
				Heartbeat: &wirev1.HeartbeatRequest{Token: token},
			},
		}
		resp := HandleEcho(req)
		ack, ok := resp.GetPayload().(*wirev1.Response_HeartbeatAck)
		if !ok {
			t.Errorf("token=%#x: not HeartbeatAck variant", token)
			continue
		}
		if got := ack.HeartbeatAck.GetToken(); got != token {
			t.Errorf("token round-trip: got %#x, want %#x", got, token)
		}
	}
}

// TestHandleEcho_UnsetPayloadProducesError locks the
// no-variant-set path: a Request with no oneof variant set
// returns a Response with an envelope-level Error so the
// controller sees a diagnosable response rather than a silently-
// empty payload.
func TestHandleEcho_UnsetPayloadProducesError(t *testing.T) {
	req := &wirev1.Request{SchemaVersion: 1, CorrelationId: 1}
	resp := HandleEcho(req)
	if resp.GetError() == nil {
		t.Fatal("unset payload should produce envelope Error; got nil")
	}
	if resp.GetError().GetCode() != "unknown_payload_variant" {
		t.Errorf("Error.code: got %q, want %q", resp.GetError().GetCode(), "unknown_payload_variant")
	}
}

// TestRun_HappyPath locks L-008 AC-05 + L-009 typed dispatch end-
// to-end: write one framed ApplyRequest, run loop, expect framed
// ApplyResponse with correlation_id preserved.
//
// @spec agent-stdio-subcommand
// @ac AC-05
func TestRun_HappyPath(t *testing.T) {
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 12345,
		Payload: &wirev1.Request_Apply{
			Apply: &wirev1.ApplyRequest{Mechanism: "file_content"},
		},
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal Request: %v", err)
	}

	var stdin bytes.Buffer
	if err := Write(&stdin, reqBytes); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err = Run(context.Background(), &stdin, &stdout, &stderr, HandleEcho)
	if err != nil {
		t.Fatalf("Run: %v; stderr=%s", err, stderr.String())
	}

	respBytes, err := Read(&stdout)
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	var resp wirev1.Response
	if err := proto.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal Response: %v", err)
	}
	if resp.GetCorrelationId() != req.GetCorrelationId() {
		t.Errorf("correlation_id: got %d, want %d", resp.GetCorrelationId(), req.GetCorrelationId())
	}
	if _, ok := resp.GetPayload().(*wirev1.Response_ApplyResp); !ok {
		t.Errorf("expected ApplyResp variant; got %T", resp.GetPayload())
	}
}

// TestRun_MultipleMixedFrames locks the loop handles a mix of
// request types in order, each producing the matching response
// variant.
func TestRun_MultipleMixedFrames(t *testing.T) {
	requests := []*wirev1.Request{
		{SchemaVersion: 1, CorrelationId: 1, Payload: &wirev1.Request_Apply{Apply: &wirev1.ApplyRequest{Mechanism: "a"}}},
		{SchemaVersion: 1, CorrelationId: 2, Payload: &wirev1.Request_Capture{Capture: &wirev1.CaptureRequest{Mechanism: "b"}}},
		{SchemaVersion: 1, CorrelationId: 3, Payload: &wirev1.Request_Heartbeat{Heartbeat: &wirev1.HeartbeatRequest{Token: 99}}},
		{SchemaVersion: 1, CorrelationId: 4, Payload: &wirev1.Request_Rollback{Rollback: &wirev1.RollbackRequest{PreState: &wirev1.WirePreState{}}}},
	}

	var stdin bytes.Buffer
	for _, req := range requests {
		b, _ := proto.Marshal(req)
		if err := Write(&stdin, b); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), &stdin, &stdout, &stderr, HandleEcho); err != nil {
		t.Fatalf("Run: %v", err)
	}

	wantVariants := []string{"*wirev1.Response_ApplyResp", "*wirev1.Response_CaptureResp", "*wirev1.Response_HeartbeatAck", "*wirev1.Response_RollbackResp"}
	for i, want := range wantVariants {
		respBytes, err := Read(&stdout)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		var resp wirev1.Response
		if err := proto.Unmarshal(respBytes, &resp); err != nil {
			t.Fatalf("unmarshal frame %d: %v", i, err)
		}
		if resp.GetCorrelationId() != uint64(i+1) {
			t.Errorf("frame %d: correlation_id = %d, want %d", i, resp.GetCorrelationId(), i+1)
		}
		gotVariant := typeOf(resp.GetPayload())
		if gotVariant != want {
			t.Errorf("frame %d: variant = %s, want %s", i, gotVariant, want)
		}
	}
}

func typeOf(v any) string {
	return fmt.Sprintf("%T", v)
}

// TestRun_EOFOnEmptyStdin locks that an immediately-closed
// stdin (no frames) returns nil cleanly. Graceful-shutdown path:
// SSH client closed without sending anything.
func TestRun_EOFOnEmptyStdin(t *testing.T) {
	var stdin, stdout, stderr bytes.Buffer
	err := Run(context.Background(), &stdin, &stdout, &stderr, HandleEcho)
	if err != nil {
		t.Errorf("empty stdin should return nil, got: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("no input → no output; got %d bytes", stdout.Len())
	}
}

// TestRun_TruncatedFrameIsError: a peer sending half a frame
// (length prefix promised N bytes, only N/2 arrived before EOF)
// terminates the loop with an error.
func TestRun_TruncatedFrameIsError(t *testing.T) {
	stdin := bytes.NewBuffer([]byte{0x00, 0x00, 0x00, 0x64}) // length=100, no body

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

// TestRun_MalformedProtoIsError: a peer sending a frame whose
// payload isn't a valid wirev1.Request triggers a protobuf
// decode error, the loop terminates.
func TestRun_MalformedProtoIsError(t *testing.T) {
	var stdin bytes.Buffer
	if err := Write(&stdin, []byte("not a Request")); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), &stdin, &stdout, &stderr, HandleEcho)
	if err == nil {
		t.Error("malformed proto should be an error; got nil")
	}
	if stderr.Len() == 0 {
		t.Error("stderr should carry a diagnostic; got empty")
	}
}

// TestRun_PreCancelledContext locks the between-frames ctx
// check (L-008 spec C-07). Pre-cancelled context short-circuits
// the loop without attempting a Read.
//
// @spec agent-stdio-subcommand
// @ac AC-06
func TestRun_PreCancelledContext(t *testing.T) {
	var stdin bytes.Buffer
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 1,
		Payload:       &wirev1.Request_Heartbeat{Heartbeat: &wirev1.HeartbeatRequest{Token: 1}},
	}
	reqBytes, _ := proto.Marshal(req)
	_ = Write(&stdin, reqBytes)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

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
		t.Errorf("no frame should be echoed when ctx is pre-cancelled; got %d bytes", stdout.Len())
	}
}
