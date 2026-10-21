package evidence_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
)

type signingVector struct {
	Name      string          `json:"name"`
	Envelope  json.RawMessage `json:"envelope"`
	Canonical []byte          `json:"canonical"`
	Tagged    []byte          `json:"tagged"`
	Signature []byte          `json:"signature"`
	PublicKey []byte          `json:"public_key"`
	Hash      string          `json:"hash"`
}

func loadVectors(t *testing.T, path string) ([]signingVector, ed25519.PrivateKey) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Seed    string          `json:"seed_hex"`
		Vectors []signingVector `json:"vectors"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(file.Seed)
	if err != nil {
		t.Fatal(err)
	}
	return file.Vectors, ed25519.NewKeyFromSeed(seed)
}
func vectorEnvelope(t *testing.T, raw []byte) *api.EvidenceEnvelope {
	t.Helper()
	var env api.EvidenceEnvelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&env); err != nil {
		t.Fatal(err)
	}
	return &env
}
func cloneEnvelope(t *testing.T, env *api.EvidenceEnvelope) *api.EvidenceEnvelope {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return vectorEnvelope(t, b)
}
func v2Fixture(t *testing.T) (*api.EvidenceEnvelope, *evidence.Signer) {
	t.Helper()
	vectors, private := loadVectors(t, "testdata/v1-vectors.json")
	env := vectorEnvelope(t, vectors[0].Envelope)
	env.SchemaVersion = "v2"
	s := evidence.New(private)
	var err error
	env.Signature, env.SigningKeyID, err = s.Sign(env)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Verify(env)
	if err != nil || result == nil || !result.Valid {
		t.Fatalf("valid v2 baseline: %v %+v", err, result)
	}
	t.Log("valid v2 baseline verified before tamper")
	return env, s
}

// @spec evidence-envelope
// @ac AC-02 AC-03 AC-04
func TestReleasedV1Vectors(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-02")
	vectors, private := loadVectors(t, "testdata/v1-vectors.json")
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			env := vectorEnvelope(t, v.Envelope)
			canonical, err := evidence.CanonicalForTest(env)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(canonical, v.Canonical) {
				t.Fatalf("historical canonical bytes changed\ngot %s\nwant %s", canonical, v.Canonical)
			}
			hash := sha256.Sum256(canonical)
			if hex.EncodeToString(hash[:]) != v.Hash {
				t.Fatal("historical hash changed")
			}
			tagged := append([]byte("kensa-evidence-envelope-v1\x00"), canonical...)
			if !bytes.Equal(tagged, v.Tagged) || !ed25519.Verify(v.PublicKey, tagged, v.Signature) {
				t.Fatal("released tagged bytes/signature do not match")
			}
			s := evidence.New(private)
			sig, _, err := s.Sign(env)
			if err != nil || !bytes.Equal(sig, v.Signature) {
				t.Fatalf("historical signing bytes changed: %v", err)
			}
			result, err := s.Verify(env)
			if err != nil || !result.Valid || result.EnvelopeHash != hash {
				t.Fatalf("historical verification: %v %+v", err, result)
			}
			env.RollbackResults = append(env.RollbackResults, api.RollbackResult{StepIndex: 99, Success: false, Detail: "unauthenticated edit"})
			if len(env.RollbackResults) > 1 {
				env.RollbackResults[0].Success = !env.RollbackResults[0].Success
			}
			result, err = s.Verify(env)
			if err != nil || !result.Valid || result.EnvelopeHash != hash {
				t.Fatalf("v1 historical limitation changed: %v %+v", err, result)
			}
		})
	}
}

// @spec evidence-envelope
// @ac AC-03
func TestV2RollbackTamper(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	base, s := v2Fixture(t)
	edits := map[string]func(*api.EvidenceEnvelope){
		"StepIndex": func(e *api.EvidenceEnvelope) { e.RollbackResults[0].StepIndex++ },
		"Mechanism": func(e *api.EvidenceEnvelope) { e.RollbackResults[0].Mechanism += "-edit" },
		"Success":   func(e *api.EvidenceEnvelope) { e.RollbackResults[0].Success = !e.RollbackResults[0].Success },
		"Detail":    func(e *api.EvidenceEnvelope) { e.RollbackResults[0].Detail += "-edit" },
		"PartialRestore": func(e *api.EvidenceEnvelope) {
			e.RollbackResults[0].PartialRestore = !e.RollbackResults[0].PartialRestore
		},
		"Source": func(e *api.EvidenceEnvelope) { e.RollbackResults[0].Source = "deadman" },
		"ExecutedAt": func(e *api.EvidenceEnvelope) {
			e.RollbackResults[0].ExecutedAt = e.RollbackResults[0].ExecutedAt.Add(time.Nanosecond)
		},
		"add": func(e *api.EvidenceEnvelope) {
			e.RollbackResults = append(e.RollbackResults, api.RollbackResult{StepIndex: 42})
		},
		"remove": func(e *api.EvidenceEnvelope) { e.RollbackResults = e.RollbackResults[:1] },
		"reorder": func(e *api.EvidenceEnvelope) {
			e.RollbackResults[0], e.RollbackResults[1] = e.RollbackResults[1], e.RollbackResults[0]
		},
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			e := cloneEnvelope(t, base)
			edit(e)
			r, err := s.Verify(e)
			if err == nil || r == nil || r.Valid || !strings.Contains(err.Error(), "signature does not match") {
				t.Fatalf("tamper must cause signature mismatch, got %v %+v", err, r)
			}
		})
	}
}

// @spec evidence-envelope
// @ac AC-01 AC-03
func TestV2FieldCoverage(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-01")
	env, s := v2Fixture(t)
	canonical, err := evidence.CanonicalForTest(env)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &fields); err != nil {
		t.Fatal(err)
	}
	typ := reflect.TypeOf(*env)
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Name == "Signature" || f.Name == "SigningKeyID" {
			continue
		}
		key := strings.Split(f.Tag.Get("json"), ",")[0]
		if _, ok := fields[key]; !ok {
			t.Errorf("declared field %s omitted from v2", f.Name)
		}
	}
	edits := map[string]func(*api.EvidenceEnvelope){
		"SchemaVersion":    func(e *api.EvidenceEnvelope) { e.SchemaVersion = "v1" },
		"TransactionID":    func(e *api.EvidenceEnvelope) { e.TransactionID[0] ^= 1 },
		"RuleID":           func(e *api.EvidenceEnvelope) { e.RuleID += "edit" },
		"HostID":           func(e *api.EvidenceEnvelope) { e.HostID += "edit" },
		"FleetID":          func(e *api.EvidenceEnvelope) { e.FleetID += "edit" },
		"StartedAt":        func(e *api.EvidenceEnvelope) { e.StartedAt = e.StartedAt.Add(time.Nanosecond) },
		"FinishedAt":       func(e *api.EvidenceEnvelope) { e.FinishedAt = e.FinishedAt.Add(time.Nanosecond) },
		"PreStateBundle":   func(e *api.EvidenceEnvelope) { e.PreStateBundle[0].Data["large"] = json.Number("9007199254740994") },
		"ApplySteps":       func(e *api.EvidenceEnvelope) { e.ApplySteps[0].Detail += "edit" },
		"ValidatorResults": func(e *api.EvidenceEnvelope) { e.ValidatorResults[0].Passed = true },
		"Decision":         func(e *api.EvidenceEnvelope) { e.Decision = api.StatusCommitted },
		"Severity":         func(e *api.EvidenceEnvelope) { e.Severity = "low" },
		"PostStateBundle": func(e *api.EvidenceEnvelope) {
			e.PostStateBundle = append(e.PostStateBundle, api.PreState{Mechanism: "edit"})
		},
		"FrameworkRefs": func(e *api.EvidenceEnvelope) { e.FrameworkRefs = append(e.FrameworkRefs, api.FrameworkRef{}) },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			e := cloneEnvelope(t, env)
			edit(e)
			r, err := s.Verify(e)
			if err == nil || r == nil || r.Valid || !strings.Contains(err.Error(), "signature does not match") {
				t.Fatalf("covered field edit not rejected by mismatch: %v %+v", err, r)
			}
		})
	}
}

// @spec evidence-envelope
// @ac AC-02 AC-09 AC-11
func TestV2NormalizationAndPurity(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-09")
	env, s := v2Fixture(t)
	before, _ := json.Marshal(env)
	for i := 0; i < 3; i++ {
		r, err := s.Verify(env)
		if err != nil || !r.Valid {
			t.Fatalf("repeat verify: %v", err)
		}
	}
	after, _ := json.Marshal(env)
	if !bytes.Equal(before, after) {
		t.Fatal("verification mutated envelope")
	}
	a := cloneEnvelope(t, env)
	a.RollbackResults = nil
	b := cloneEnvelope(t, a)
	b.RollbackResults = []api.RollbackResult{}
	ca, err := evidence.CanonicalForTest(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := evidence.CanonicalForTest(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca, cb) || !bytes.Contains(ca, []byte(`"rollback_results":[]`)) {
		t.Fatal("nil/empty rollback normalization")
	}
	e := cloneEnvelope(t, env)
	e.RollbackResults[0].ExecutedAt = e.RollbackResults[0].ExecutedAt.UTC()
	c1, _ := evidence.CanonicalForTest(env)
	c2, _ := evidence.CanonicalForTest(e)
	if !bytes.Equal(c1, c2) {
		t.Fatal("equivalent rollback UTC timestamps differ")
	}
}

// @spec evidence-envelope
// @ac AC-04 AC-06 AC-09 AC-11
func TestVersionedAPIPolicySeparation(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-11")
	v2, s := v2Fixture(t)
	vectors, _ := loadVectors(t, "testdata/v1-vectors.json")
	for _, env := range []*api.EvidenceEnvelope{vectorEnvelope(t, vectors[0].Envelope), v2} {
		t.Run(env.SchemaVersion, func(t *testing.T) {
			env.SigningKeyID = "malformed-metadata"
			r, err := s.VerifyEnvelope(env)
			if err != nil || !r.Valid || !reflect.DeepEqual(r.Warnings, []api.VerifyWarning{api.KeyIDMismatch}) {
				t.Fatalf("frozen cryptographic semantics changed: %v %+v", err, r)
			}
			other, err := evidence.Generate()
			if err != nil {
				t.Fatal(err)
			}
			other.WithRotationHistory(s.Public())
			r, err = other.Verify(env)
			if err != nil || !r.Valid || !reflect.DeepEqual(r.Warnings, []api.VerifyWarning{api.KeyRotation, api.KeyIDMismatch}) {
				t.Fatalf("rotation semantics: %v %+v", err, r)
			}
			c, _ := evidence.CanonicalForTest(env)
			wrongTag := "kensa-evidence-envelope-v1\x00"
			if env.SchemaVersion == "v1" {
				wrongTag = "kensa-evidence-envelope-v2\x00"
			}
			_, private := loadVectors(t, "testdata/v1-vectors.json")
			env.Signature = ed25519.Sign(private, append([]byte(wrongTag), c...))
			r, err = s.Verify(env)
			if err == nil || r == nil || r.Valid {
				t.Fatal("cross-domain signature accepted")
			}
		})
	}
	for _, version := range []string{"", "v99"} {
		e := cloneEnvelope(t, v2)
		e.SchemaVersion = version
		if _, err := s.Verify(e); err == nil {
			t.Fatalf("accepted version %q", version)
		}
		if _, _, err := s.Sign(e); err == nil {
			t.Fatalf("signed unknown version %q", version)
		}
	}
}

// @spec evidence-envelope
// @ac AC-02 AC-04
func TestIndependentPythonV2Vectors(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-02")
	vectors, private := loadVectors(t, "testdata/v2-vectors.json")
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			env := vectorEnvelope(t, v.Envelope)
			content, err := evidence.CanonicalForTest(env)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(content, v.Canonical) {
				t.Fatalf("Go/Python v2 byte mismatch\ngot %s\nwant %s", content, v.Canonical)
			}
			tagged := append([]byte("kensa-evidence-envelope-v2\x00"), content...)
			if !bytes.Equal(tagged, v.Tagged) || !ed25519.Verify(v.PublicKey, tagged, v.Signature) {
				t.Fatal("independent domain/signature mismatch")
			}
			s := evidence.New(private)
			sig, _, err := s.Sign(env)
			if err != nil || !bytes.Equal(sig, v.Signature) {
				t.Fatalf("independent signature mismatch: %v", err)
			}
			result, err := s.Verify(env)
			if err != nil || !result.Valid || hex.EncodeToString(result.EnvelopeHash[:]) != v.Hash {
				t.Fatalf("independent verification/hash: %v %+v", err, result)
			}
		})
	}
}
