package evidence_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
)

// TestSign_RedactsPreStateBundleAndStillVerifies proves the signature is
// computed over the redacted envelope, so the signed record carries no
// credential value yet verifies successfully.
//
// @spec store-redaction
// @ac AC-04
func TestSign_RedactsPreStateBundleAndStillVerifies(t *testing.T) {
	t.Log("// @spec store-redaction")
	t.Log("// @ac AC-04")

	s, err := evidence.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	env := &api.EvidenceEnvelope{
		SchemaVersion: "v1",
		TransactionID: uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		RuleID:        "some-rule",
		HostID:        "host-01",
		StartedAt:     now,
		FinishedAt:    now.Add(time.Second),
		Decision:      api.StatusCommitted,
		PreStateBundle: []api.PreState{
			{
				StepIndex:  0,
				Mechanism:  "config_set",
				Capturable: true,
				Data: map[string]any{
					"path":     "/etc/app.conf",
					"password": "hunter2", // pragma: allowlist secret
				},
				CapturedAt: now,
			},
		},
	}

	sig, keyID, err := s.Sign(env)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	env.Signature = sig
	env.SigningKeyID = keyID

	// (a) no credential value survives in the signed envelope.
	if got := env.PreStateBundle[0].Data["password"]; got != "<redacted>" { // pragma: allowlist secret
		t.Errorf("password not redacted in signed envelope: %v", got)
	}
	if got := env.PreStateBundle[0].Data["path"]; got != "/etc/app.conf" {
		t.Errorf("non-sensitive path altered: %v", got)
	}

	// (b) the signature verifies against the (redacted) envelope.
	res, err := s.Verify(env)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !res.Valid {
		t.Errorf("signed-then-redacted envelope failed verification: %+v", res)
	}
}
