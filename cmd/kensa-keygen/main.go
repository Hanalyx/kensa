// Command kensa-keygen generates an Ed25519 keypair for evidence-
// envelope signing. M-012 deliverable. Output files are
// PEM-encoded — the format `openssl pkey -in <keyid>.priv` /
// `openssl pkey -in <keyid>.pub -pubin` will read.
//
// Usage:
//
//	kensa-keygen [--out DIR] [--key-id NAME] [--force]
//
// Default output directory:
//   - $KENSA_CONFIG_DIR/keys/ if KENSA_CONFIG_DIR is set
//   - $XDG_CONFIG_HOME/kensa/keys/ if XDG_CONFIG_HOME is set
//   - $HOME/.config/kensa/keys/ otherwise
//
// Files written:
//
//	<keyid>.priv   PEM-encoded ed25519 private key, mode 0600
//	<keyid>.pub    PEM-encoded ed25519 public key,  mode 0644
//
// Default <keyid> is the lower-hex SHA-256 of the public key bytes
// (matches the convention in internal/evidence/signer.go).
// Override with --key-id NAME for human-readable filenames like
// `production` or `host-a-prod`.
//
// Exit codes:
//
//	0   keypair written successfully; key_id printed to stdout
//	1   runtime error (write failed, output dir creation failed, etc.)
//	2   usage error (bad flag, file collision without --force)
//
// Subsequent C-060 (Phase 5b) wires the consumer side: an evidence.
// LoadSigner that reads these files, plus the KENSA_SIGNING_KEY
// CLI flag / env var on the kensa binary that points at the
// .priv file.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/pflag"
)

// nowUnix returns the current Unix timestamp as a string. Wrapped
// in a variable so tests can swap in a deterministic clock if
// they ever need to assert specific archived-file names.
var nowUnix = func() int64 {
	return time.Now().Unix()
}

const (
	// File-mode constants. Private key is 0600 (owner read/write
	// only) — leaking the private key compromises every evidence
	// envelope it ever signs. Public key is 0644 (world-readable)
	// since it's by-design distributable.
	privKeyMode os.FileMode = 0o600
	pubKeyMode  os.FileMode = 0o644

	// Default-directory file mode. 0700 so only the owner can list
	// or enter, keeping the .priv file's permissions meaningful
	// even when a tooling chain accidentally weakens umask.
	defaultDirMode os.FileMode = 0o700
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable harness. Returns the desired exit code.
// stdout receives the success message (the key_id); stderr
// receives error messages.
func run(args []string, stdout, stderr io.Writer) int {
	fs := pflag.NewFlagSet("kensa-keygen", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		outDir   string
		keyID    string
		force    bool
	)
	fs.BoolVarP(&showHelp, "help", "h", false, "show this help and exit")
	fs.StringVarP(&outDir, "out", "o", "", "output directory (default: $KENSA_CONFIG_DIR/keys, then $XDG_CONFIG_HOME/kensa/keys, then ~/.config/kensa/keys)")
	fs.StringVar(&keyID, "key-id", "", "key identifier used as the filename stem (default: lower-hex SHA-256 of the public key)")
	fs.BoolVar(&force, "force", false, "overwrite existing key files at the target path (DESTRUCTIVE)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printUsage(stdout, fs)
			return 0
		}
		fmt.Fprintf(stderr, "kensa-keygen: %v\nrun 'kensa-keygen --help' for usage\n", err)
		return 2
	}
	if showHelp {
		printUsage(stdout, fs)
		return 0
	}

	if outDir == "" {
		var err error
		outDir, err = defaultKeyDir()
		if err != nil {
			fmt.Fprintf(stderr, "kensa-keygen: cannot resolve default key directory: %v\n", err)
			return 1
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(stderr, "kensa-keygen: ed25519 generation failed: %v\n", err)
		return 1
	}

	if keyID == "" {
		keyID = computeKeyID(pub)
	}

	if err := os.MkdirAll(outDir, defaultDirMode); err != nil {
		fmt.Fprintf(stderr, "kensa-keygen: mkdir %s: %v\n", outDir, err)
		return 1
	}

	privPath := filepath.Join(outDir, keyID+".priv")
	pubPath := filepath.Join(outDir, keyID+".pub")

	if !force {
		for _, p := range []string{privPath, pubPath} {
			if _, err := os.Stat(p); err == nil {
				fmt.Fprintf(stderr,
					"kensa-keygen: refusing to overwrite existing file %s (pass --force to overwrite, or pick a different --key-id)\n",
					p)
				return 2
			} else if !os.IsNotExist(err) {
				fmt.Fprintf(stderr, "kensa-keygen: stat %s: %v\n", p, err)
				return 1
			}
		}
	} else {
		// --force overwrite: archive the OLD .pub before clobbering
		// it. Auditors verifying past envelopes need the old public
		// key — once we overwrite it, that capability is gone
		// forever. The archive is `<keyid>.pub.archived.<unix-ts>`,
		// kept at mode 0644 alongside the new files. The .priv is
		// NOT archived (the operator's choice to overwrite is
		// deliberate; preserving the old private key on disk just
		// expands the secret-leak surface).
		if _, err := os.Stat(pubPath); err == nil {
			tsName := fmt.Sprintf("%s.archived.%d", pubPath, nowUnix())
			if err := os.Rename(pubPath, tsName); err != nil {
				fmt.Fprintf(stderr,
					"kensa-keygen: --force: failed to archive prior %s to %s: %v\n",
					pubPath, tsName, err)
				return 1
			}
			fmt.Fprintf(stderr,
				"kensa-keygen: --force: archived prior public key to %s (auditors verifying past envelopes need this file)\n",
				tsName)
		}
	}

	privPEM, err := encodePrivateKey(priv)
	if err != nil {
		fmt.Fprintf(stderr, "kensa-keygen: encode private key: %v\n", err)
		return 1
	}
	pubPEM, err := encodePublicKey(pub)
	if err != nil {
		fmt.Fprintf(stderr, "kensa-keygen: encode public key: %v\n", err)
		return 1
	}

	if err := writeFile(privPath, privPEM, privKeyMode); err != nil {
		fmt.Fprintf(stderr, "kensa-keygen: write %s: %v\n", privPath, err)
		return 1
	}
	if err := writeFile(pubPath, pubPEM, pubKeyMode); err != nil {
		// Try to clean up the .priv we just wrote so we don't
		// leave an orphan private key without its public half.
		_ = os.Remove(privPath)
		fmt.Fprintf(stderr, "kensa-keygen: write %s: %v\n", pubPath, err)
		return 1
	}

	fmt.Fprintf(stdout, "%s\n", keyID)
	fmt.Fprintf(stderr, "kensa-keygen: wrote %s (mode %o)\n", privPath, privKeyMode)
	fmt.Fprintf(stderr, "kensa-keygen: wrote %s (mode %o)\n", pubPath, pubKeyMode)
	// SHA-256 fingerprint in the ssh-keygen-style format for
	// operators who recognize that shape from years of OpenSSH
	// muscle memory. base64 (not hex) so it's the SAME bytes
	// presented in the conventional CLI form.
	fpHash := sha256.Sum256(pub)
	fp := base64.StdEncoding.EncodeToString(fpHash[:])
	fmt.Fprintf(stderr, "kensa-keygen: pub fingerprint: SHA256:%s\n", fp)
	return 0
}

// printUsage writes operator-facing help to w.
func printUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa-keygen [flags]

Generate an Ed25519 keypair for evidence-envelope signing (M-012).

Output files:
  <keyid>.priv  PEM-encoded ed25519 private key, mode 0600
  <keyid>.pub   PEM-encoded ed25519 public key,  mode 0644

Default output directory (in priority order):
  $KENSA_CONFIG_DIR/keys/
  $XDG_CONFIG_HOME/kensa/keys/
  $HOME/.config/kensa/keys/

Default <keyid> is the lower-hex SHA-256 of the public key bytes
(matches the kensa-go signer's key-identity convention). Override
with --key-id NAME for human-readable filenames.

Flags:
%s
Examples:
  kensa-keygen
  kensa-keygen --key-id production
  kensa-keygen --out /var/lib/kensa/keys --force

After generation, the printed key_id is the filename stem used by
the kensa binary's --signing-key flag (Phase 5b / C-060) to locate
the corresponding files.

EXIT CODES

  0  keypair written successfully; key_id printed to stdout
  1  runtime error (write failed, output dir creation failed, etc.)
  2  usage error (bad flag, file collision without --force)

SECURITY

The .priv file is the cryptographic root of every evidence
envelope it signs. Treat it like an SSH private key:

  - NEVER commit .priv to version control (git, mercurial, etc.)
  - NEVER include .priv in container images or build artifacts
  - NEVER email, paste into chat, or share .priv over insecure
    channels
  - Store .priv only on hosts that need to sign envelopes; the
    .pub file is what verifiers need, NOT .priv

Compromise of .priv allows an attacker to forge evidence envelopes
indistinguishable from authentic ones. If you suspect leak, rotate
immediately AND treat past envelopes signed by the leaked key as
suspect.

KEY ROTATION

To rotate, generate a new keypair with a fresh --key-id (e.g.
'production-2026Q3'). Add the OLD <keyid>.pub to your verifier's
key_history (in v1.1, via 'kensa verify --key-history /path/to/
old.pub'). Start signing new envelopes with the new --signing-key.

DO NOT delete or overwrite the old .pub file: auditors verifying
envelopes signed by the old key need it. If you must overwrite an
existing key_id with --force, kensa-keygen archives the prior
public key to '<keyid>.pub.archived.<unix-ts>' so verification of
past envelopes remains possible.

If the old .priv leaks: rotate immediately AND treat the leaked
key as compromised. Cryptographic-revocation distinct from
rotation is a v1.1 follow-up (today every key in your verifier's
history is trusted).
`, fs.FlagUsages())
}

// defaultKeyDir resolves the operator's default key directory using
// the precedence chain documented in printUsage.
func defaultKeyDir() (string, error) {
	if v := os.Getenv("KENSA_CONFIG_DIR"); v != "" {
		return filepath.Join(v, "keys"), nil
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "kensa", "keys"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("UserHomeDir: %w", err)
	}
	return filepath.Join(home, ".config", "kensa", "keys"), nil
}

// computeKeyID matches the convention in
// internal/evidence/signer.go computeKeyID — lower-hex SHA-256 of
// the raw public key bytes (the 32-byte ed25519 form, NOT the
// PEM-wrapped form). Cross-reference deliberately: kensa-keygen's
// default keyID equals what the signer would compute for the same
// public key, so operators don't have to think about which name
// to use.
func computeKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// encodePrivateKey wraps the ed25519 private key in PKCS#8 then
// PEM. PKCS#8 is the modern standard for Ed25519 private keys
// (RFC 8410); the resulting file reads with `openssl pkey -in
// <keyid>.priv` and `ssh-keygen -m PEM -f <keyid>.priv`.
func encodePrivateKey(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("PKCS#8 marshal: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// encodePublicKey wraps the ed25519 public key in PKIX then PEM.
// Matches the format `openssl pkey -in <keyid>.pub -pubin` reads.
func encodePublicKey(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("PKIX marshal: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// writeFile creates path with the given mode and writes data. The
// O_EXCL flag combined with the !force check above means a
// pre-existing file at the target path is treated as a user error,
// not silently overwritten. With --force, we delete first then
// re-create with O_CREATE so the mode bits are applied regardless
// of any pre-existing file's umask-derived mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	_ = os.Remove(path) // ignore "not exists" — handled above
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
