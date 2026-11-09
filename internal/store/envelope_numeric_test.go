package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
	"github.com/Hanalyx/kensa/internal/store"
)

// @spec evidence-envelope
// @ac AC-12
func TestVersionedNumericSQLiteRead(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-12")
	path := os.Getenv("PT04_NUMBER_VECTORS")
	if path == "" {
		path = "../evidence/testdata/numeric-vectors.json"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Name     string          `json:"name"`
			Envelope json.RawMessage `json:"envelope"`
			Public   []byte          `json:"public_key"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, v := range doc.Vectors {
		version, name, _ := strings.Cut(v.Name, "/")
		// The identical test is also run over released v0.12.0 source.
		if filter := os.Getenv("PT04_NUMBER_VERSION"); filter != "" && version != filter {
			continue
		}
		for _, spelling := range []string{"original", "decimal", "exponent", "rounded-neighbor"} {
			if spelling != "original" && name != "integer" && name != "exact-large-integer" {
				continue
			}
			if spelling == "rounded-neighbor" && name != "exact-large-integer" {
				continue
			}
			t.Run(v.Name+"/"+spelling, func(t *testing.T) {
				var compact bytes.Buffer
				if err := json.Compact(&compact, v.Envelope); err != nil {
					t.Fatal(err)
				}
				input := compact.String()
				number := "1000"
				if name == "exact-large-integer" {
					number = "9007199254740992"
				}
				switch spelling {
				case "decimal":
					input = strings.ReplaceAll(input, `"number":`+number, `"number":`+number+".0")
				case "exponent":
					exponent := "1e3"
					if name == "exact-large-integer" {
						exponent = "9.007199254740992e15"
					}
					input = strings.ReplaceAll(input, `"number":`+number, `"number":`+exponent)
				case "rounded-neighbor":
					input = strings.ReplaceAll(input, `"number":`+number, `"number":9007199254740993`)
				}
				var env api.EvidenceEnvelope
				decoder := json.NewDecoder(strings.NewReader(input))
				decoder.UseNumber()
				if err := decoder.Decode(&env); err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				dbPath := filepath.Join(t.TempDir(), "evidence.db")
				s, err := store.OpenSQLite(ctx, dbPath)
				if err != nil {
					t.Fatal(err)
				}
				result := &api.TransactionResult{TransactionID: env.TransactionID, Status: env.Decision, StartedAt: env.StartedAt, FinishedAt: env.FinishedAt, Envelope: &env}
				if err := s.PersistResult(ctx, result); err != nil {
					t.Fatal(err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				// Inject the original lexical representation into the real
				// persisted column so setup cannot normalize away the test.
				if _, err := db.Exec("UPDATE transactions SET envelope_json=? WHERE id=?", input, env.TransactionID.String()); err != nil {
					t.Fatal(err)
				}
				s, err = store.OpenSQLite(ctx, dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				rec, err := s.Get(ctx, env.TransactionID)
				if err != nil {
					t.Fatal(err)
				}
				wantValid := version == "v2" && spelling == "original"
				if version == "v1" {
					switch name {
					case "integer", "float-tiny", "float-large", "float-exponent", "exact-large-integer":
						wantValid = true
					}
				}
				verified, err := evidence.NewVerifier(ed25519.PublicKey(v.Public)).Verify(rec.Envelope)
				valid := verified != nil && verified.Valid
				t.Logf("version=%s spelling=%s decoded=%T(%v) valid=%v error=%v", version, spelling, rec.Envelope.PreStateBundle[0].Data["number"], rec.Envelope.PreStateBundle[0].Data["number"], valid, err)
				if valid != wantValid || (wantValid && err != nil) || (!wantValid && (err == nil || !strings.Contains(err.Error(), "signature does not match"))) {
					t.Fatalf("SQLite numeric verification: valid=%v want=%v error=%v", valid, wantValid, err)
				}
				var unchanged string
				if err := db.QueryRow("SELECT envelope_json FROM transactions WHERE id=?", env.TransactionID.String()).Scan(&unchanged); err != nil || unchanged != input {
					t.Fatalf("audit read rewrote original evidence: %v", err)
				}
			})
		}
	}
}
