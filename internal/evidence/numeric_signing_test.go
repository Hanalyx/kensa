package evidence_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
)

func checkNumericVector(t *testing.T, v signingVector, private ed25519.PrivateKey, env *api.EvidenceEnvelope) {
	t.Helper()
	content, err := evidence.CanonicalForTest(env)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	tagged := append([]byte("kensa-evidence-envelope-"+env.SchemaVersion+"\x00"), content...)
	if !bytes.Equal(content, v.Canonical) || !bytes.Equal(tagged, v.Tagged) || hex.EncodeToString(hash[:]) != v.Hash {
		t.Fatalf("numeric canonical/domain/hash mismatch: %s", content)
	}
	s := evidence.New(private)
	sig, _, err := s.Sign(env)
	if err != nil || !bytes.Equal(sig, v.Signature) || !ed25519.Verify(v.PublicKey, tagged, sig) {
		t.Fatalf("numeric signature mismatch: %v", err)
	}
	result, err := s.Verify(env)
	if err != nil || !result.Valid || result.EnvelopeHash != hash {
		t.Fatalf("numeric verification/hash: %v %+v", err, result)
	}
}

// @spec evidence-envelope
// @ac AC-02
func TestVersionedNumericCanonicalVectors(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-02")
	vectors, private := loadVectors(t, "testdata/numeric-vectors.json")
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			env := vectorEnvelope(t, v.Envelope)
			// Reuse the same exact-byte, hash and signature checks as the
			// released vectors, including lossless decimal/exponent inputs.
			checkNumericVector(t, v, private, env)
		})
	}
}

// @spec evidence-envelope
// @ac AC-03
func TestVersionedNumericDecimalTamper(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	vectors, private := loadVectors(t, "testdata/numeric-vectors.json")
	for _, v := range vectors {
		if !strings.HasSuffix(v.Name, "/decimal") {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			env := vectorEnvelope(t, v.Envelope)
			s := evidence.New(private)
			if result, err := s.Verify(env); err != nil || !result.Valid {
				t.Fatalf("positive control: %v %+v", err, result)
			}
			env.PreStateBundle[0].Data["number"] = json.Number("1.00000000000000001")
			result, err := s.Verify(env)
			if err == nil || result == nil || result.Valid || !strings.Contains(err.Error(), "signature does not match") {
				t.Fatalf("rounded decimal tamper: %v %+v", err, result)
			}
		})
	}
}
