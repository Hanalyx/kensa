package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
)

// validKeyID gates the format of envelope.signing_key_id before we
// concatenate it into a filesystem path. Without this guard, a
// crafted envelope with `signing_key_id: "../../etc/evil"` resolves
// to an attacker-controlled .pub elsewhere on disk via
// filepath.Join's path-traversal-friendly behavior. The signer
// always emits a 64-char lower-hex SHA-256 — anything else is
// either tampered or from a different signer; either way, refuse.
var validKeyID = regexp.MustCompile(`^[a-f0-9]{64}$`)

const legacyV1Warning = "Legacy v1 signature is valid; rollback results are not authenticated."

// runVerify implements `kensa verify <evidence-file>` (C-060).
// Reads a JSON-encoded EvidenceEnvelope from disk, looks up the
// corresponding public key by signing_key_id in a configured
// trust directory, runs Ed25519 verification, exits 0 / 1 / 2
// per the standard kensa contract.
//
// Trust-directory model: each public key lives at
// `<trust-dir>/<keyID>.pub` (matches kensa-keygen's default
// output filename pattern). The verifier reads the envelope,
// extracts signing_key_id, opens that single .pub file,
// constructs a verify-only signer, runs Verify.
//
// Falling back to "try every .pub in the dir" was rejected
// during the spec phase: it's slow on large trust dirs and
// hides key-id-mismatch tampering signals.
func runVerify(args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"trust-dir": true, "format": true,
	})

	fs := pflag.NewFlagSet("verify", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp       bool
		trustDir       string
		format         string
		quiet          bool
		acceptLegacyV1 bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVar(&trustDir, "trust-dir", "", "directory of .pub files to look up signing_key_id (default matches kensa-keygen's output dir)")
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text or json")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")
	fs.BoolVar(&acceptLegacyV1, "accept-legacy-v1", false, "accept a valid legacy v1 signature; rollback results remain unauthenticated")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printVerifyUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa verify --help'", err)
	}
	if showHelp {
		printVerifyUsage(os.Stdout, fs)
		return nil
	}

	switch format {
	case "text", "json":
	default:
		return NewUsageError(fmt.Sprintf("--format %q: must be 'text' or 'json'", format))
	}

	posArgs := fs.Args()
	if len(posArgs) != 1 {
		return NewUsageError(fmt.Sprintf(
			"kensa verify requires exactly 1 positional <evidence-file> argument (got %d)", len(posArgs)))
	}
	evidencePath := posArgs[0]

	envelope, err := loadEnvelope(evidencePath)
	if err != nil {
		// Per spec C-060 exit-code table: missing file / malformed
		// JSON are both usage errors (exit 2). loadEnvelope wraps
		// JSON parse errors with a "malformed JSON" prefix; the
		// "no such file" case is already a clear errno. Both go
		// through WrapUsageError so runCLI maps to exit 2.
		// Distinguishing "file vanished mid-read" from "operator
		// typo" was a candidate refinement (P2 review finding) but
		// would diverge from AC-04 which locks "missing file
		// exits 2" without a sub-discriminator.
		return WrapUsageError("read envelope", err)
	}

	// Unsigned-by-design records: an errored or recovered transaction is
	// recorded in the log for audit but is NOT signed (engine-transaction
	// C-06). Report that honestly instead of the generic "empty
	// signing_key_id" path, so an operator is told why there is nothing to
	// verify rather than being left to infer tampering.
	if len(envelope.Signature) == 0 &&
		(envelope.Decision == api.StatusErrored || envelope.Decision == api.StatusRecovered) {
		return fmt.Errorf(
			"envelope records an unsigned %s transaction: recorded for audit but not signed by design; there is no signature to verify",
			envelope.Decision)
	}

	// Reject empty or malformed signing_key_id BEFORE joining into
	// the trust-dir path. Otherwise:
	//   - `signing_key_id: ""` → trustDir/.pub (an exotic filename)
	//   - `signing_key_id: "../etc/evil"` → /etc/evil.pub (path
	//     traversal — attacker plants a .pub matching their own
	//     keypair, signs an envelope claiming it, kensa verify
	//     reports VALID).
	// validKeyID enforces 64-char lower-hex SHA-256, the only
	// format the kensa signer ever emits.
	if envelope.SigningKeyID == "" {
		return errors.New("envelope has empty signing_key_id; cannot identify signing key")
	}
	if !validKeyID.MatchString(envelope.SigningKeyID) {
		return fmt.Errorf("envelope signing_key_id has unexpected format (want 64-char lower-hex SHA-256): %q", envelope.SigningKeyID)
	}

	if trustDir == "" {
		trustDir, err = defaultTrustDir()
		if err != nil {
			return fmt.Errorf("resolve default trust dir: %w", err)
		}
	}

	pubPath := filepath.Join(trustDir, envelope.SigningKeyID+".pub")
	verifier, err := evidence.LoadVerifier(pubPath)
	if err != nil {
		// Verify-time key-not-found is exit 1 (runtime: "this
		// envelope's key isn't in our trust dir") not exit 2
		// (usage: "you typed bad flags"). Mirrors the C-047 /
		// C-048 ErrNotFound convention.
		return fmt.Errorf("public key for signing_key_id=%s not found in trust dir %s: %w",
			envelope.SigningKeyID, trustDir, err)
	}

	result, verifyErr := verifier.Verify(envelope)
	valid := verifyErr == nil && result != nil && result.Valid
	accepted := valid && (envelope.SchemaVersion == "v2" || acceptLegacyV1)
	rollbackAuthenticated := valid && envelope.SchemaVersion == "v2"
	var warnings []string
	if result != nil {
		for _, warning := range result.Warnings {
			warnings = append(warnings, string(warning))
		}
	}
	// This warning describes a verified limitation, not a successful policy
	// decision. It is mandatory even when quiet suppresses the output body.
	if valid && envelope.SchemaVersion == "v1" {
		fmt.Fprintln(os.Stderr, legacyV1Warning)
		warnings = append(warnings, legacyV1Warning)
		if !accepted {
			verifyErr = errors.New("legacy v1 evidence is not accepted by default; use --accept-legacy-v1 to accept unauthenticated rollback results")
		}
	}

	out := bodyOut(quiet)
	if format == "json" {
		// Marshal the result + a top-level Valid flag for clean
		// jq parsing. verifyErr (if any) goes into the message
		// field as a string.
		payload := struct {
			Valid                        bool     `json:"valid"`
			Accepted                     bool     `json:"accepted"`
			RollbackResultsAuthenticated bool     `json:"rollback_results_authenticated"`
			KeyID                        string   `json:"key_id"`
			Warnings                     []string `json:"warnings,omitempty"`
			Error                        string   `json:"error,omitempty"`
		}{
			Valid:                        valid,
			Accepted:                     accepted,
			RollbackResultsAuthenticated: rollbackAuthenticated,
			Warnings:                     warnings,
		}
		if result != nil {
			payload.KeyID = result.KeyID
		}
		if verifyErr != nil {
			payload.Error = verifyErr.Error()
		}
		if err := json.NewEncoder(out).Encode(payload); err != nil {
			return err
		}
	} else {
		// Policy rejection must not relabel a matching signature INVALID.
		textErr := verifyErr
		if valid {
			textErr = nil
		}
		writeVerifyText(out, result, textErr, evidencePath, envelope, pubPath)
		fmt.Fprintf(out, "  accepted:        %t\n  rollback_results_authenticated: %t\n", accepted, rollbackAuthenticated)
	}

	if verifyErr != nil || !accepted {
		// Exit 1 (runtime: signature didn't validate). Wrap in
		// a non-UsageError so runCLI maps to exit 1.
		if verifyErr != nil {
			return verifyErr
		}
		return errors.New("verification failed")
	}
	return nil
}

// loadEnvelope reads + parses a JSON-encoded EvidenceEnvelope
// from disk. Returns the parsed struct or a wrapped error.
func loadEnvelope(path string) (*api.EvidenceEnvelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env api.EvidenceEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&env); err != nil {
		return nil, fmt.Errorf("malformed JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("malformed JSON: expected exactly one envelope")
	}
	if env.SchemaVersion == "v1" {
		// The released CLI decoded generic v1 numbers as float64 before
		// canonicalization. Retain that exact historical behavior, including
		// its precision limits. v2 keeps the lossless decode above. Select
		// once by version; never retry a different form after verification.
		env = api.EvidenceEnvelope{}
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, fmt.Errorf("malformed JSON: %w", err)
		}
	}
	return &env, nil
}

// defaultTrustDir matches kensa-keygen's default output
// directory precedence chain so an operator who ran keygen
// without --out can verify without --trust-dir.
func defaultTrustDir() (string, error) {
	if v := os.Getenv("KENSA_CONFIG_DIR"); v != "" {
		return filepath.Join(v, "keys"), nil
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "kensa", "keys"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "kensa", "keys"), nil
}

// writeVerifyText renders the verify result for human consumption.
func writeVerifyText(w io.Writer, result *api.VerifyResult, verifyErr error,
	evidencePath string, env *api.EvidenceEnvelope, pubPath string) {
	fmt.Fprintf(w, "kensa verify %s\n", evidencePath)
	fmt.Fprintf(w, "  signing_key_id:  %s\n", env.SigningKeyID)
	fmt.Fprintf(w, "  trust dir lookup: %s\n", pubPath)

	switch {
	case verifyErr != nil:
		fmt.Fprintf(w, "  status:          INVALID — %v\n", verifyErr)
	case result == nil:
		fmt.Fprintf(w, "  status:          INVALID — no result\n")
	case !result.Valid:
		fmt.Fprintln(w, "  status:          INVALID")
	default:
		fmt.Fprintln(w, "  status:          VALID")
		fmt.Fprintf(w, "  matched key_id:  %s\n", result.KeyID)
		if len(result.Warnings) > 0 {
			fmt.Fprintln(w, "  warnings:")
			for _, warn := range result.Warnings {
				fmt.Fprintf(w, "    - %s\n", warn)
			}
		}
	}
}

func printVerifyUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa verify <evidence-file> [flags]

Verify the Ed25519 signature on a kensa evidence-envelope JSON
file. Looks up the public key by the envelope's signing_key_id
field in a trust directory (a directory of .pub files produced
by kensa-keygen).

Trust directory default (in priority order):
  $KENSA_CONFIG_DIR/keys/
  $XDG_CONFIG_HOME/kensa/keys/
  $HOME/.config/kensa/keys/

Override with --trust-dir DIR.

Exit codes:
  0  signature is valid and accepted by CLI policy
  1  invalid/unverified signature or policy rejection (including v1 by default)
  2  usage error (missing file, bad flag, malformed JSON)

Flags:
%s
Examples:
  kensa verify evidence.json
  kensa verify evidence.json --trust-dir /etc/kensa/keys
  kensa verify evidence.json --format json | jq -r .accepted
  kensa verify historical-v1.json --accept-legacy-v1

v2 authenticates rollback results. Historical v1 does not; accepting it
requires --accept-legacy-v1 and always warns on stderr, even under --quiet:
  Legacy v1 signature is valid; rollback results are not authenticated.
JSON valid describes cryptographic validity; accepted describes CLI policy.
rollback_results_authenticated is true only for a verified v2 record.
Upgrade verifiers before producers: older verifiers reject v2. New
production envelopes use v2, including paths that remain unsigned.
Keep historical evidence unchanged. A signature does not prove restoration.

CRITICAL FAILURE MODES (exit 1, not 2):
  - Signature mismatch: envelope was tampered after signing
  - Unknown key: signing_key_id has no .pub in the trust dir
  - Wrong key: signature doesn't match the .pub file we found
  - Schema-version unknown: envelope is from a future kensa version

CRYPTOGRAPHIC WARNINGS (CLI acceptance policy still applies):
  - signed_by_rotated_key: matched against a non-active key in
    the rotation history (envelope is authentic but signed by
    a key that's been rotated out)
  - signing_key_id_mismatch: the matched key's id disagrees
    with the envelope's signing_key_id field (the signature is
    real but the metadata is inconsistent — investigate)
`, fs.FlagUsages())
}
