package evidence

// Disk-loaders for Ed25519 keys produced by kensa-keygen (M-012).
//
// kensa-keygen writes:
//   <keyid>.priv   PEM-encoded PKCS#8 Ed25519 private key (mode 0600)
//   <keyid>.pub    PEM-encoded PKIX Ed25519 public  key  (mode 0644)
//
// LoadSigner reads a .priv and returns a *Signer that can both Sign
// (with that key) and Verify (against that key's public half).
// LoadVerifier reads a .pub and returns a *Signer that can ONLY
// Verify — calling Sign on a verify-only signer would need a
// private key that was never loaded.
//
// Trust-directory model (C-060): `kensa verify <evidence-file>`
// looks up <signing_key_id>.pub in a configured directory. The
// loader API here is the building block.

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadSigner reads a PEM-encoded PKCS#8 Ed25519 private key from
// path and returns a *Signer that can Sign + Verify with it.
//
// Failure modes wrapped with "evidence: LoadSigner:" prefix:
//   - Read error (missing file, permission denied)
//   - PEM decode failure (file isn't PEM)
//   - PKCS#8 parse failure (PEM block isn't a private key)
//   - Wrong algorithm (key isn't Ed25519)
func LoadSigner(path string) (*Signer, error) {
	// Refuse to load a .priv whose mode is group/other-readable.
	// Mirrors OpenSSH's StrictModes default: a key file readable
	// by anyone other than the owner is, by definition, a leaked
	// key. Loading it silently would let a co-tenant who's already
	// read the file forge envelopes that look indistinguishable
	// from authentic. Lstat (not Stat) so we also catch a symlink
	// pointing at a world-readable file in another directory.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("evidence: LoadSigner: %w", err)
	}
	if info.Mode()&0o077 != 0 {
		return nil, fmt.Errorf("evidence: LoadSigner: %s has insecure mode %o (private key must not be group/other-readable; chmod 600)", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("evidence: LoadSigner: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("evidence: LoadSigner: %s is not a PEM file", path)
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("evidence: LoadSigner: %s PEM type is %q, want \"PRIVATE KEY\"", path, block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("evidence: LoadSigner: PKCS#8 parse %s: %w", path, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("evidence: LoadSigner: %s is not an Ed25519 key (got %T)", path, parsed)
	}
	return New(priv), nil
}

// LoadVerifier reads a PEM-encoded PKIX Ed25519 public key from
// path and returns a *Signer that can Verify (only). Sign() on
// the returned signer will fail because no private key was loaded.
//
// Used by `kensa verify <evidence-file>` — the auditor receives
// just the .pub file, not the .priv.
//
// The keyID is set from the filename (path's basename, sans the
// .pub extension) so the verifier can compare envelope.signing_key_id
// against it for the KeyIDMismatch warning per M-012's contract.
func LoadVerifier(path string) (*Signer, error) {
	// Reject symlinks in the trust dir. Otherwise an attacker who
	// can write into the trust dir (or who can run kensa-keygen
	// targeting it) can plant a symlink at <hash>.pub pointing at
	// a public key they DO control, satisfying the verify lookup
	// for envelopes signed with their own key while masquerading
	// as a different signing_key_id. Lstat → reject mode&Symlink.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("evidence: LoadVerifier: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("evidence: LoadVerifier: %s is a symlink (trust dir must contain regular files only)", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("evidence: LoadVerifier: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("evidence: LoadVerifier: %s is not a PEM file", path)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("evidence: LoadVerifier: %s PEM type is %q, want \"PUBLIC KEY\"", path, block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("evidence: LoadVerifier: PKIX parse %s: %w", path, err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("evidence: LoadVerifier: %s is not an Ed25519 key (got %T)", path, parsed)
	}
	return NewVerifier(pub), nil
}
