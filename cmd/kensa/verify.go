package main

import (
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
		showHelp bool
		trustDir string
		format   string
		quiet    bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVar(&trustDir, "trust-dir", "", "directory of .pub files to look up signing_key_id (default matches kensa-keygen's output dir)")
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text or json")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")

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

	out := bodyOut(quiet)
	if format == "json" {
		// Marshal the result + a top-level Valid flag for clean
		// jq parsing. verifyErr (if any) goes into the message
		// field as a string.
		payload := struct {
			Valid    bool                `json:"valid"`
			KeyID    string              `json:"key_id"`
			Warnings []api.VerifyWarning `json:"warnings,omitempty"`
			Error    string              `json:"error,omitempty"`
		}{
			Valid: result != nil && result.Valid,
		}
		if result != nil {
			payload.KeyID = result.KeyID
			payload.Warnings = result.Warnings
		}
		if verifyErr != nil {
			payload.Error = verifyErr.Error()
		}
		if err := json.NewEncoder(out).Encode(payload); err != nil {
			return err
		}
	} else {
		writeVerifyText(out, result, verifyErr, evidencePath, envelope, pubPath)
	}

	if verifyErr != nil || result == nil || !result.Valid {
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
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("malformed JSON: %w", err)
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
  0  signature is valid (envelope is authentic)
  1  signature is INVALID (tampered, wrong key, missing key)
  2  usage error (missing file, bad flag, malformed JSON)

Flags:
%s
Examples:
  kensa verify evidence.json
  kensa verify evidence.json --trust-dir /etc/kensa/keys
  kensa verify evidence.json --format json | jq -r .valid

CRITICAL FAILURE MODES (exit 1, not 2):
  - Signature mismatch: envelope was tampered after signing
  - Unknown key: signing_key_id has no .pub in the trust dir
  - Wrong key: signature doesn't match the .pub file we found
  - Schema-version unknown: envelope is from a future kensa version

VALIDATION SUCCESS WARNINGS (still exit 0):
  - signed_by_rotated_key: matched against a non-active key in
    the rotation history (envelope is authentic but signed by
    a key that's been rotated out)
  - signing_key_id_mismatch: the matched key's id disagrees
    with the envelope's signing_key_id field (the signature is
    real but the metadata is inconsistent — investigate)
`, fs.FlagUsages())
}
