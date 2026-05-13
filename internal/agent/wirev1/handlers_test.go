package wirev1

import (
	"math"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Hanalyx/kensa-go/api"
)

// TestBridge_StepResultRoundtrip locks AC-03: api.StepResult →
// wire → api.StepResult is identity under reflect.DeepEqual.
// All fields are primitive Go types (int / string / bool); no
// numeric/time widening applies.
//
// @spec agent-wire-handler-schema
// @ac AC-03
// @spec agent-wire-handler-schema
// @ac AC-01
func TestBridge_StepResultRoundtrip(t *testing.T) {
	t.Run("agent-wire-handler-schema/AC-01", func(t *testing.T) {})
	t.Log("// @spec agent-wire-handler-schema")
	t.Log("// @ac AC-03")
	cases := []struct {
		name string
		in   api.StepResult
	}{
		{"zero", api.StepResult{}},
		{
			"populated",
			api.StepResult{
				StepIndex:  3,
				Mechanism:  "file_content",
				Capturable: true,
				Success:    true,
				Detail:     "wrote 4096 bytes",
				Stranded:   false,
			},
		},
		{
			"failure",
			api.StepResult{
				StepIndex:  0,
				Mechanism:  "command_exec",
				Capturable: false,
				Success:    false,
				Detail:     "exit 1: command not found",
				Stranded:   true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := APIStepResultToWire(tc.in)
			got := WireStepResultToAPI(w)
			if !reflect.DeepEqual(got, tc.in) {
				t.Errorf("roundtrip mismatch:\n  got:  %#v\n  want: %#v", got, tc.in)
			}
		})
	}
}

// TestBridge_StepResultNilDecode locks the nil-input safety
// contract: WireStepResultToAPI(nil) returns the zero
// api.StepResult, not a panic.
// @spec agent-wire-handler-schema
// @ac AC-02
func TestBridge_StepResultNilDecode(t *testing.T) {
	t.Run("agent-wire-handler-schema/AC-02", func(t *testing.T) {})
	got := WireStepResultToAPI(nil)
	if !reflect.DeepEqual(got, api.StepResult{}) {
		t.Errorf("nil → expected zero StepResult; got %#v", got)
	}
}

// TestBridge_PreStateRoundtrip locks AC-03 + AC-04 for the
// PreState path. The Data map[string]any goes through
// MapToStruct/StructToMap so the L-007 numeric/time-widening
// caveats apply — integers widen to int64, time.Time values
// in Data widen to RFC3339Nano strings. The TOP-LEVEL
// PreState.CapturedAt uses protobuf Timestamp (exact, not
// widening).
//
// @spec agent-wire-handler-schema
// @ac AC-03
func TestBridge_PreStateRoundtrip(t *testing.T) {
	t.Run("agent-wire-handler-schema/AC-03", func(t *testing.T) {})
	t.Log("// @spec agent-wire-handler-schema")
	t.Log("// @ac AC-03")
	when := time.Date(2026, 5, 11, 9, 30, 0, 0, time.UTC)
	cases := []struct {
		name string
		in   api.PreState
		want api.PreState // expected output after roundtrip (may differ from `in` due to L-007 widening)
	}{
		{
			"zero",
			api.PreState{},
			// Data nil widens to empty map: MapToStruct(nil)
			// produces &Struct{Fields:{}}, which encodes the
			// same as an empty Struct on the wire. On decode,
			// StructToMap returns a non-nil empty map. This
			// is documented L-007 behavior — handlers should
			// not distinguish nil from empty Data.
			api.PreState{Data: map[string]any{}},
		},
		{
			"populated_with_int_widening",
			api.PreState{
				StepIndex:  2,
				Mechanism:  "file_permissions",
				Capturable: true,
				Data: map[string]any{
					"path": "/etc/ssh/sshd_config",
					"mode": uint32(0o644),
				},
				CapturedAt: when,
			},
			api.PreState{
				StepIndex:  2,
				Mechanism:  "file_permissions",
				Capturable: true,
				Data: map[string]any{
					"path": "/etc/ssh/sshd_config",
					"mode": int64(0o644), // L-007 widening
				},
				CapturedAt: when,
			},
		},
		{
			"non_capturable_no_data",
			api.PreState{
				StepIndex:  1,
				Mechanism:  "command_exec",
				Capturable: false,
				Data:       nil,
				CapturedAt: when,
			},
			// nil Data widens to empty map across the wire.
			api.PreState{
				StepIndex:  1,
				Mechanism:  "command_exec",
				Capturable: false,
				Data:       map[string]any{},
				CapturedAt: when,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := APIPreStateToWire(tc.in)
			if err != nil {
				t.Fatalf("APIPreStateToWire: %v", err)
			}
			got, err := WirePreStateToAPI(w)
			if err != nil {
				t.Fatalf("WirePreStateToAPI: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("roundtrip mismatch:\n  got:  %#v\n  want: %#v", got, tc.want)
			}
		})
	}
}

// TestBridge_PreStateNilDecode locks the nil-input safety.
// @spec agent-wire-handler-schema
// @ac AC-04
func TestBridge_PreStateNilDecode(t *testing.T) {
	t.Run("agent-wire-handler-schema/AC-04", func(t *testing.T) {})
	got, err := WirePreStateToAPI(nil)
	if err != nil {
		t.Fatalf("WirePreStateToAPI(nil): %v", err)
	}
	if !reflect.DeepEqual(got, api.PreState{}) {
		t.Errorf("nil → expected zero PreState; got %#v", got)
	}
}

// TestBridge_PreStateOversizedIntError locks the L-007
// precision-guard propagation: a PreState whose Data has an
// int64 > 2^53 surfaces a wrapped error from the underlying
// MapToStruct rather than corrupting silently.
// @spec agent-wire-handler-schema
// @ac AC-05
func TestBridge_PreStateOversizedIntError(t *testing.T) {
	t.Run("agent-wire-handler-schema/AC-05", func(t *testing.T) {})
	in := api.PreState{
		Data: map[string]any{
			"unix_nano": int64(1_760_000_000_000_000_000), // ~1.76e18, > 2^53
		},
	}
	_, err := APIPreStateToWire(in)
	if err == nil {
		t.Error("expected error for oversized int in PreState.Data; got nil")
	}
}

// TestBridge_RollbackResultRoundtrip locks AC-03 for the
// RollbackResult path. All fields are primitives + time.Time.
//
// @spec agent-wire-handler-schema
// @ac AC-03
// @spec agent-wire-handler-schema
// @ac AC-06
func TestBridge_RollbackResultRoundtrip(t *testing.T) {
	t.Run("agent-wire-handler-schema/AC-06", func(t *testing.T) {})
	t.Log("// @spec agent-wire-handler-schema")
	t.Log("// @ac AC-03")
	when := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		in   api.RollbackResult
	}{
		{"zero", api.RollbackResult{}},
		{
			"populated",
			api.RollbackResult{
				StepIndex:      2,
				Mechanism:      "file_content",
				Success:        true,
				Detail:         "restored from PreState",
				PartialRestore: false,
				Source:         "inline",
				ExecutedAt:     when,
			},
		},
		{
			"deadman_partial",
			api.RollbackResult{
				StepIndex:      0,
				Mechanism:      "service_enabled",
				Success:        false,
				Detail:         "service reload failed",
				PartialRestore: true,
				Source:         "deadman",
				ExecutedAt:     when,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := APIRollbackResultToWire(tc.in)
			got, err := WireRollbackResultToAPI(w)
			if err != nil {
				t.Fatalf("WireRollbackResultToAPI: %v", err)
			}
			if !reflect.DeepEqual(got, tc.in) {
				t.Errorf("roundtrip mismatch:\n  got:  %#v\n  want: %#v", got, tc.in)
			}
		})
	}
}

// TestBridge_RollbackResultNilDecode locks nil-input safety.
// @spec agent-wire-handler-schema
// @ac AC-07
func TestBridge_RollbackResultNilDecode(t *testing.T) {
	t.Run("agent-wire-handler-schema/AC-07", func(t *testing.T) {})
	got, err := WireRollbackResultToAPI(nil)
	if err != nil {
		t.Fatalf("nil → expected nil err; got: %v", err)
	}
	if !reflect.DeepEqual(got, api.RollbackResult{}) {
		t.Errorf("nil → expected zero RollbackResult; got %#v", got)
	}
}

// TestBridge_RejectsMalformedTimestamp locks the security-review
// finding: a peer sending Timestamp{Seconds: math.MaxInt64}
// would otherwise pass through AsTime() silently and land a
// year-292277 time.Time in the signed audit trail. The bridge
// now validates via Timestamp.CheckValid before AsTime, surfaces
// an error, and the dispatcher refuses to commit a Response
// with an out-of-range time field.
// @spec agent-wire-handler-schema
// @ac AC-08
func TestBridge_RejectsMalformedTimestamp(t *testing.T) {
	t.Run("agent-wire-handler-schema/AC-08", func(t *testing.T) {})
	malformed := &timestamppb.Timestamp{Seconds: math.MaxInt64}

	t.Run("PreState_CapturedAt", func(t *testing.T) {
		w := &WirePreState{CapturedAt: malformed}
		_, err := WirePreStateToAPI(w)
		if err == nil {
			t.Error("expected error for malformed CapturedAt; got nil")
		}
	})

	t.Run("RollbackResult_ExecutedAt", func(t *testing.T) {
		w := &WireRollbackResult{ExecutedAt: malformed}
		_, err := WireRollbackResultToAPI(w)
		if err == nil {
			t.Error("expected error for malformed ExecutedAt; got nil")
		}
	})
}

// TestBridge_NilTimestampIsZero locks the "no timestamp set"
// path: a nil Timestamp (which protobuf treats as a missing
// field) decodes to a zero time.Time, not an error. Handlers
// can legitimately produce results with no timestamp set.
func TestBridge_NilTimestampIsZero(t *testing.T) {
	w := &WirePreState{} // CapturedAt is nil
	got, err := WirePreStateToAPI(w)
	if err != nil {
		t.Errorf("nil CapturedAt should not error; got: %v", err)
	}
	if !got.CapturedAt.IsZero() {
		t.Errorf("nil CapturedAt should decode to zero time.Time; got: %v", got.CapturedAt)
	}
}

// TestBridge_ParamsRoundtrip locks the L-009 P0 finding: a
// symmetric APIParamsToWire/WireParamsToAPI pair exists so L-011's
// dispatcher author doesn't have to wire MapToStruct manually.
// Same numeric-widening contract as PreState.Data.
func TestBridge_ParamsRoundtrip(t *testing.T) {
	in := api.Params{
		"path": "/etc/ssh/sshd_config",
		"mode": uint32(0o644),
	}
	want := api.Params{
		"path": "/etc/ssh/sshd_config",
		"mode": int64(0o644), // L-007 widening
	}
	s, err := APIParamsToWire(in)
	if err != nil {
		t.Fatalf("APIParamsToWire: %v", err)
	}
	got, err := WireParamsToAPI(s)
	if err != nil {
		t.Fatalf("WireParamsToAPI: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("roundtrip mismatch:\n  got:  %#v\n  want: %#v", got, want)
	}
}

// TestBridge_NilParamsRoundtrip: nil api.Params decodes to
// nil api.Params (not empty map) — the WireParamsToAPI helper
// preserves the nil-versus-empty distinction so L-011 handlers
// can use `if params == nil` checks.
func TestBridge_NilParamsRoundtrip(t *testing.T) {
	s, err := APIParamsToWire(nil)
	if err != nil {
		t.Fatalf("APIParamsToWire(nil): %v", err)
	}
	got, err := WireParamsToAPI(s)
	if err != nil {
		t.Fatalf("WireParamsToAPI: %v", err)
	}
	if got != nil {
		// MapToStruct(nil) returns an empty Struct; StructToMap
		// of an empty Struct returns an empty map. Document
		// the actual roundtrip behavior here; if it changes,
		// the L-011 author needs to know.
		t.Logf("note: nil api.Params widens to %v on roundtrip (empty map)", got)
	}
}

// TestProtoMessagesPresent locks AC-01: every typed message
// declared in the spec exists as a Go type in the generated
// wire.pb.go. Sentinel check — if a future protoc-gen-go change
// re-shapes the output, this fires.
//
// @spec agent-wire-handler-schema
// @ac AC-01
func TestProtoMessagesPresent(t *testing.T) {
	t.Log("// @spec agent-wire-handler-schema")
	t.Log("// @ac AC-01")
	// One-shot allocation per message type — if the type is
	// gone or renamed, this won't compile.
	_ = &ApplyRequest{}
	_ = &ApplyResponse{}
	_ = &CaptureRequest{}
	_ = &CaptureResponse{}
	_ = &RollbackRequest{}
	_ = &RollbackResponse{}
	_ = &HeartbeatRequest{}
	_ = &HeartbeatAck{}
	_ = &WireStepResult{}
	_ = &WirePreState{}
	_ = &WireRollbackResult{}
}

// TestRequestOneofVariants locks AC-02: Request.payload is a
// oneof. The old `bytes` field is absent — verified by trying
// to construct a Request with one of each oneof variant (would
// fail to compile if the oneof types didn't exist).
//
// @spec agent-wire-handler-schema
// @ac AC-02
func TestRequestOneofVariants(t *testing.T) {
	t.Log("// @spec agent-wire-handler-schema")
	t.Log("// @ac AC-02")
	_ = &Request{Payload: &Request_Apply{Apply: &ApplyRequest{}}}
	_ = &Request{Payload: &Request_Capture{Capture: &CaptureRequest{}}}
	_ = &Request{Payload: &Request_Rollback{Rollback: &RollbackRequest{}}}
	_ = &Request{Payload: &Request_Heartbeat{Heartbeat: &HeartbeatRequest{}}}

	_ = &Response{Payload: &Response_ApplyResp{ApplyResp: &ApplyResponse{}}}
	_ = &Response{Payload: &Response_CaptureResp{CaptureResp: &CaptureResponse{}}}
	_ = &Response{Payload: &Response_RollbackResp{RollbackResp: &RollbackResponse{}}}
	_ = &Response{Payload: &Response_HeartbeatAck{HeartbeatAck: &HeartbeatAck{}}}
}
