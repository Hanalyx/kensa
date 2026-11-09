package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
)

func buildVerifyProcess(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "kensa")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", binary, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	return binary
}
func verifyProcess(t *testing.T, binary string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(binary, append([]string{"verify"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exit := 0
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			exit = e.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	t.Logf("argv=%q exit=%d stdout=%q stderr=%q", args, exit, stdout.String(), stderr.String())
	return exit, stdout.String(), stderr.String()
}
func processVector(t *testing.T, version string) (map[string]any, []byte) {
	t.Helper()
	b, err := os.ReadFile("../../internal/evidence/testdata/" + version + "-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Envelope json.RawMessage `json:"envelope"`
			Public   []byte          `json:"public_key"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	input := doc.Vectors[0].Envelope
	if version == "v1" {
		// The fixed API vector contains an integer the historical CLI
		// cannot round-trip. Build a separate historically CLI-readable
		// fixture for the acceptance-policy matrix; never rewrite vectors.
		var historical api.EvidenceEnvelope
		if err := json.Unmarshal(input, &historical); err != nil {
			t.Fatal(err)
		}
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = byte(i)
		}
		historical.Signature, historical.SigningKeyID, err = evidence.New(ed25519.NewKeyFromSeed(seed)).Sign(&historical)
		if err != nil {
			t.Fatal(err)
		}
		input, err = json.Marshal(historical)
		if err != nil {
			t.Fatal(err)
		}
	}
	var env map[string]any
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := decoder.Decode(&env); err != nil {
		t.Fatal(err)
	}
	return env, doc.Vectors[0].Public
}
func writeProcessEnvelope(t *testing.T, env map[string]any) string {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "envelope.json")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func versionedProcessFixture(t *testing.T) (string, string) {
	t.Helper()
	binary := buildVerifyProcess(t)
	trust := t.TempDir()
	v1, pub := processVector(t, "v1")
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trust, v1["signing_key_id"].(string)+".pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	return binary, trust
}

// @spec cli-verify-subcommand
// @ac AC-01 AC-02 AC-03 AC-04 AC-09 AC-10
func TestVerifyVersionedProcess(t *testing.T) {
	t.Log("// @spec cli-verify-subcommand")
	t.Log("// @ac AC-09")
	binary, trust := versionedProcessFixture(t)
	for _, version := range []string{"v1", "v2"} {
		for _, legacy := range []bool{false, true} {
			for _, format := range []string{"text", "json"} {
				for _, quiet := range []bool{false, true} {
					name := version + "/" + format
					if legacy {
						name += "/legacy"
					}
					if quiet {
						name += "/quiet"
					}
					t.Run(name, func(t *testing.T) {
						env, _ := processVector(t, version)
						path := writeProcessEnvelope(t, env)
						before, _ := os.ReadFile(path)
						args := []string{path, "--trust-dir", trust, "--format", format}
						if legacy {
							args = append(args, "--accept-legacy-v1")
						}
						if quiet {
							args = append(args, "--quiet")
						}
						exit, stdout, stderr := verifyProcess(t, binary, args...)
						accepted := version == "v2" || legacy
						wantExit := 0
						if !accepted {
							wantExit = 1
						}
						if exit != wantExit {
							t.Fatalf("exit=%d want=%d stdout=%s stderr=%s", exit, wantExit, stdout, stderr)
						}
						if version == "v1" {
							if !strings.Contains(stderr, legacyV1Warning) {
								t.Fatalf("mandatory limitation absent: %q", stderr)
							}
						} else if strings.Contains(stderr, legacyV1Warning) {
							t.Fatalf("unexpected legacy warning: %q", stderr)
						}
						switch {
						case quiet:
							if stdout != "" {
								t.Fatalf("quiet body: %q", stdout)
							}
						case format == "json":
							var body struct {
								Valid         bool     `json:"valid"`
								Accepted      bool     `json:"accepted"`
								Authenticated bool     `json:"rollback_results_authenticated"`
								Warnings      []string `json:"warnings"`
							}
							if err := json.Unmarshal([]byte(stdout), &body); err != nil {
								t.Fatalf("JSON: %v %q", err, stdout)
							}
							if !body.Valid || body.Accepted != accepted || body.Authenticated != (version == "v2") {
								t.Fatalf("wrong JSON policy: %+v", body)
							}
							if version == "v1" && !reflect.DeepEqual(body.Warnings, []string{legacyV1Warning}) {
								t.Fatalf("JSON limitation: %+v", body.Warnings)
							}
						default:
							if !strings.Contains(stdout, "status:          VALID") || !strings.Contains(stdout, "accepted:") {
								t.Fatalf("missing validity/acceptance: %q", stdout)
							}
						}
						after, _ := os.ReadFile(path)
						if !bytes.Equal(before, after) {
							t.Fatal("CLI rewrote evidence")
						}
					})
				}
			}
		}
	}
}

// @spec cli-verify-subcommand
// @ac AC-10
func TestVerifyVersionedFailures(t *testing.T) {
	t.Log("// @spec cli-verify-subcommand")
	t.Log("// @ac AC-10")
	binary, trust := versionedProcessFixture(t)
	failures := []struct {
		name   string
		mutate func(map[string]any)
		trust  string
	}{
		{"bad-signature", func(e map[string]any) {
			sig, err := base64.StdEncoding.DecodeString(e["signature"].(string))
			if err != nil {
				t.Fatal(err)
			}
			sig[0] ^= 1
			e["signature"] = base64.StdEncoding.EncodeToString(sig)
		}, trust},
		{"bad-signature-length", func(e map[string]any) { e["signature"] = strings.Repeat("A", 88) }, trust},
		{"unsigned", func(e map[string]any) { e["signature"] = nil }, trust},
		{"missing-key", func(e map[string]any) {}, t.TempDir()},
		{"malformed-key-id", func(e map[string]any) { e["signing_key_id"] = "../outside" }, trust},
		{"empty-version", func(e map[string]any) { e["schema_version"] = "" }, trust},
		{"unknown-version", func(e map[string]any) { e["schema_version"] = "v99" }, trust},
		{"swapped-version", func(e map[string]any) { e["schema_version"] = "v1" }, trust},
		{"rollback-edit", func(e map[string]any) { e["rollback_results"].([]any)[0].(map[string]any)["Success"] = false }, trust},
	}
	for _, tc := range failures {
		for _, flag := range []bool{false, true} {
			t.Run(tc.name, func(t *testing.T) {
				env, _ := processVector(t, "v2")
				tc.mutate(env)
				args := []string{writeProcessEnvelope(t, env), "--trust-dir", tc.trust, "--format", "json"}
				if flag {
					args = append(args, "--accept-legacy-v1")
				}
				exit, stdout, stderr := verifyProcess(t, binary, args...)
				if exit != 1 {
					t.Fatalf("failure bypassed: exit=%d stdout=%s stderr=%s", exit, stdout, stderr)
				}
				if strings.Contains(stderr, legacyV1Warning) || strings.Contains(stdout, `"rollback_results_authenticated":true`) {
					t.Fatalf("false authentication claim: %s %s", stdout, stderr)
				}
			})
		}
	}
	t.Run("legacy-rollback-edit", func(t *testing.T) {
		env, _ := processVector(t, "v1")
		env["rollback_results"].([]any)[0].(map[string]any)["Success"] = false
		exit, stdout, stderr := verifyProcess(t, binary, writeProcessEnvelope(t, env), "--trust-dir", trust, "--accept-legacy-v1", "--format", "json")
		if exit != 0 || !strings.Contains(stdout, `"valid":true`) || !strings.Contains(stdout, `"rollback_results_authenticated":false`) || !strings.Contains(stderr, legacyV1Warning) {
			t.Fatalf("legacy limitation hidden: %d %s %s", exit, stdout, stderr)
		}
	})
	for name, data := range map[string]string{"malformed": "{", "trailing": "{} {}"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.json")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			exit, _, stderr := verifyProcess(t, binary, path, "--accept-legacy-v1")
			if exit != 2 || strings.Contains(stderr, legacyV1Warning) {
				t.Fatalf("usage exit=%d stderr=%s", exit, stderr)
			}
		})
	}
	for _, args := range [][]string{nil, {"--bogus"}, {"missing.json"}} {
		if exit, _, _ := verifyProcess(t, binary, args...); exit != 2 {
			t.Fatalf("usage %v exits %d", args, exit)
		}
	}
}
