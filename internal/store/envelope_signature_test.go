package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
	"github.com/Hanalyx/kensa/internal/store"
)

// @spec evidence-envelope
// @ac AC-02 AC-12
func TestVersionedEnvelopeSQLiteSignature(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-12")
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "evidence.db")
			s, err := store.OpenSQLite(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile("../evidence/testdata/" + version + "-vectors.json")
			if err != nil {
				t.Fatal(err)
			}
			var vectors struct {
				Vectors []struct {
					Envelope json.RawMessage `json:"envelope"`
					Public   []byte          `json:"public_key"`
				} `json:"vectors"`
			}
			if err := json.Unmarshal(raw, &vectors); err != nil {
				t.Fatal(err)
			}
			var env api.EvidenceEnvelope
			decoder := json.NewDecoder(bytes.NewReader(vectors.Vectors[0].Envelope))
			if version == "v2" {
				decoder.UseNumber()
			}
			if err := decoder.Decode(&env); err != nil {
				t.Fatal(err)
			}
			if version == "v1" {
				// Separate round-trip fixture with the historical reader's
				// float64 values. Fixed API vectors remain untouched; the
				// numeric controls explicitly retain their historical read
				// failures and rounding behavior for unrepresentable values.
				seed := make([]byte, ed25519.SeedSize)
				for i := range seed {
					seed[i] = byte(i)
				}
				env.Signature, env.SigningKeyID, err = evidence.New(ed25519.NewKeyFromSeed(seed)).Sign(&env)
				if err != nil {
					t.Fatal(err)
				}
			}
			verifier := evidence.NewVerifier(ed25519.PublicKey(vectors.Vectors[0].Public))
			before, err := verifier.Verify(&env)
			if err != nil || !before.Valid {
				t.Fatalf("valid baseline: %v", err)
			}
			result := &api.TransactionResult{TransactionID: env.TransactionID, Status: env.Decision, StartedAt: env.StartedAt, FinishedAt: env.FinishedAt, Steps: env.ApplySteps, Envelope: &env}
			if err := s.PersistResult(ctx, result); err != nil {
				t.Fatal(err)
			}
			operational := []api.PreState{{StepIndex: 0, Mechanism: "fixture", Capturable: true, Data: map[string]any{"mode": 420}, CapturedAt: env.StartedAt}}
			if err := s.PersistPreStates(ctx, env.TransactionID, operational); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var original string
			if err := db.QueryRow("SELECT envelope_json FROM transactions WHERE id=?", env.TransactionID.String()).Scan(&original); err != nil {
				t.Fatal(err)
			}
			s, err = store.OpenSQLite(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			rec, err := s.Get(ctx, env.TransactionID)
			if err != nil {
				t.Fatal(err)
			}
			after, err := verifier.Verify(rec.Envelope)
			if err != nil || after == nil || !after.Valid || after.EnvelopeHash != before.EnvelopeHash {
				t.Fatalf("signature/hash changed after SQLite reopen/Get: %v %+v", err, after)
			}
			if len(rec.Steps) != len(env.ApplySteps) || rec.Steps[0] != env.ApplySteps[0] {
				t.Fatal("operational step decoding changed")
			}
			if len(rec.PreStates) != 1 || rec.PreStates[0].Data["mode"] != float64(420) {
				t.Fatalf("operational pre-state decoding changed: %+v", rec.PreStates)
			}
			var unchanged string
			if err := db.QueryRow("SELECT envelope_json FROM transactions WHERE id=?", env.TransactionID.String()).Scan(&unchanged); err != nil {
				t.Fatal(err)
			}
			if original != unchanged {
				t.Fatal("reading evidence rewrote the stored row")
			}
		})
	}
}
