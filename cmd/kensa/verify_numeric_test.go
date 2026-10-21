package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// @spec cli-verify-subcommand
// @ac AC-09
func TestVerifyVersionedNumericProcess(t *testing.T) {
	t.Log("// @spec cli-verify-subcommand")
	t.Log("// @ac AC-09")
	binary, trust := versionedProcessFixture(t)
	raw, err := os.ReadFile("../../internal/evidence/testdata/numeric-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Name     string          `json:"name"`
			Envelope json.RawMessage `json:"envelope"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, v := range doc.Vectors {
		version, name, _ := strings.Cut(v.Name, "/")
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
				wantValid := version == "v2" && spelling == "original"
				if version == "v1" {
					switch name {
					case "integer", "float-tiny", "float-large", "float-exponent", "exact-large-integer":
						wantValid = true
					}
				}
				path := filepath.Join(t.TempDir(), "envelope.json")
				if err := os.WriteFile(path, []byte(input), 0600); err != nil {
					t.Fatal(err)
				}
				args := []string{path, "--trust-dir", trust, "--format", "json"}
				if version == "v1" {
					// Optional actual released binary supplements the fixed
					// historical outcomes; local CI need not download it.
					if old := os.Getenv("PT04_LEGACY_CLI"); old != "" {
						exit, stdout, _ := verifyProcess(t, old, args...)
						assertNumericProcess(t, exit, stdout, wantValid, wantValid)
					}
					args = append(args, "--accept-legacy-v1")
				}
				exit, stdout, stderr := verifyProcess(t, binary, args...)
				assertNumericProcess(t, exit, stdout, wantValid, wantValid)
				if strings.Contains(stderr, legacyV1Warning) != (version == "v1" && wantValid) {
					t.Fatalf("wrong legacy warning: %s", stderr)
				}
				after, err := os.ReadFile(path)
				if err != nil || string(after) != input {
					t.Fatalf("evidence rewritten: %v", err)
				}
			})
		}
	}
}

func assertNumericProcess(t *testing.T, exit int, stdout string, valid, accepted bool) {
	t.Helper()
	wantExit := 1
	if accepted {
		wantExit = 0
	}
	var body struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &body); err != nil || body.Valid != valid || exit != wantExit {
		t.Fatalf("numeric outcome: exit=%d want=%d valid=%v want=%v body=%s error=%v", exit, wantExit, body.Valid, valid, stdout, err)
	}
	if !valid && !strings.Contains(body.Error, "signature does not match") {
		t.Fatalf("numeric negative failed for an unrelated reason: %s", stdout)
	}
}
