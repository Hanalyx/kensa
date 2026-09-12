package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests run scripts/install-syft.sh for real against local fixture
// archives. A structural test that only greps the script cannot tell whether
// a failure branch still exits non-zero, so removing `exit 1` from the digest
// check would pass a text search while letting a tampered archive be
// extracted and installed. Every case here asserts the observable contract
// instead: the exit status, and whether a binary ended up in the install
// directory.
//
// No network: each case serves its archive over a file:// URL through
// SYFT_INSTALL_URL, so the outcome does not depend on GitHub being reachable.

const (
	fixtureVersion = "v1.46.0"
	fixtureReports = "syft 1.46.0" // what `syft --version` must print
)

// writeStubArchive builds a .tar.gz whose entries are (name -> content).
// Names ending in "syft" are made executable. It returns the archive path
// and its SHA-256, so a test can pin either the true digest or a wrong one.
func writeStubArchive(t *testing.T, dir, name string, entries map[string]string) (string, string) {
	t.Helper()
	stage := t.TempDir()
	var args []string
	for rel, content := range entries {
		full := filepath.Join(stage, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		mode := os.FileMode(0o644)
		if filepath.Base(rel) == "syft" {
			mode = 0o755
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
		args = append(args, rel)
	}
	archive := filepath.Join(dir, name)
	cmd := exec.Command("tar", append([]string{"-czf", archive, "-C", stage}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tar: %v: %s", err, out)
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	sum := sha256.Sum256(raw)
	return archive, hex.EncodeToString(sum[:])
}

// stubSyft is a tiny executable that reports the given version string.
func stubSyft(version string) string {
	return fmt.Sprintf("#!/usr/bin/env bash\necho %q\n", version)
}

type installResult struct {
	exitCode  int
	output    string
	installed bool
}

// runInstaller invokes the real script. url, version and digest are placed in
// the environment exactly as the workflows do; an empty value means the
// variable is left unset, which is itself a case under test.
func runInstaller(t *testing.T, installDir, url, version, digest string) installResult {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", "install-syft.sh")

	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if url != "" {
		env = append(env, "SYFT_INSTALL_URL="+url)
	}
	if version != "" {
		env = append(env, "SYFT_VERSION="+version)
	}
	if digest != "" {
		env = append(env, "SYFT_SHA256="+digest)
	}

	cmd := exec.Command("bash", script, installDir)
	cmd.Env = env
	out, err := cmd.CombinedOutput()

	code := 0
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running installer: %v", err)
		}
	}
	_, statErr := os.Stat(filepath.Join(installDir, "syft"))
	return installResult{exitCode: code, output: string(out), installed: statErr == nil}
}

func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

func requireLinuxTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("installer is a Linux CI script; GOOS=%s", runtime.GOOS)
	}
	for _, bin := range []string{"bash", "tar", "sha256sum", "curl", "install"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("required tool %q not found: %v", bin, err)
		}
	}
}

// TestInstallSyft_ValidArchive is the only case that may install anything.
//
// @spec system-supply-chain
// @ac AC-07
func TestInstallSyft_ValidArchive(t *testing.T) {
	t.Log("// @spec system-supply-chain")
	t.Log("// @ac AC-07")
	requireLinuxTools(t)

	dir := t.TempDir()
	archive, digest := writeStubArchive(t, dir, "good.tar.gz", map[string]string{
		"syft":      stubSyft(fixtureReports),
		"README.md": "readme\n",
	})
	installDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}

	got := runInstaller(t, installDir, "file://"+archive, fixtureVersion, digest)
	if got.exitCode != 0 {
		t.Fatalf("exit=%d, want 0\n%s", got.exitCode, got.output)
	}
	if !got.installed {
		t.Fatal("valid archive did not install a syft binary")
	}
	out, err := exec.Command(filepath.Join(installDir, "syft"), "--version").Output()
	if err != nil {
		t.Fatalf("installed binary not runnable: %v", err)
	}
	if strings.TrimSpace(string(out)) != fixtureReports {
		t.Errorf("installed binary reports %q, want %q", strings.TrimSpace(string(out)), fixtureReports)
	}
}

// TestInstallSyft_FailsClosed drives every corruption of the inputs and
// requires exit 1 with nothing installed. Each subtest is the observable
// contract, so deleting a failure branch from the script fails here even
// though the script's text would still mention the check.
//
// @spec system-supply-chain
// @ac AC-07
func TestInstallSyft_FailsClosed(t *testing.T) {
	t.Log("// @spec system-supply-chain")
	t.Log("// @ac AC-07")
	requireLinuxTools(t)

	const wrongDigest = "0000000000000000000000000000000000000000000000000000000000000000"

	cases := []struct {
		name        string
		entries     map[string]string
		url         func(archive string) string
		version     string
		digest      func(real string) string
		wantMessage string
	}{
		{
			name:        "digest mismatch",
			entries:     map[string]string{"syft": stubSyft(fixtureReports)},
			version:     fixtureVersion,
			digest:      func(string) string { return wrongDigest },
			wantMessage: "digest mismatch",
		},
		{
			name:        "download failure",
			entries:     map[string]string{"syft": stubSyft(fixtureReports)},
			url:         func(archive string) string { return "file://" + archive + ".missing" },
			version:     fixtureVersion,
			digest:      func(real string) string { return real },
			wantMessage: "could not be downloaded",
		},
		{
			name:        "no syft at archive root",
			entries:     map[string]string{"nested/syft": stubSyft(fixtureReports), "README.md": "x\n"},
			version:     fixtureVersion,
			digest:      func(real string) string { return real },
			wantMessage: "did not contain a syft binary",
		},
		{
			name:        "version mismatch",
			entries:     map[string]string{"syft": stubSyft("syft 1.45.9")},
			version:     fixtureVersion,
			digest:      func(real string) string { return real },
			wantMessage: "reports 'syft 1.45.9'",
		},
		{
			name:    "missing SYFT_VERSION",
			entries: map[string]string{"syft": stubSyft(fixtureReports)},
			version: "",
			digest:  func(real string) string { return real },
		},
		{
			name:    "missing SYFT_SHA256",
			entries: map[string]string{"syft": stubSyft(fixtureReports)},
			version: fixtureVersion,
			digest:  func(string) string { return "" },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			archive, realDigest := writeStubArchive(t, dir, "case.tar.gz", tc.entries)
			installDir := filepath.Join(dir, "bin")
			if err := os.MkdirAll(installDir, 0o755); err != nil {
				t.Fatal(err)
			}
			url := "file://" + archive
			if tc.url != nil {
				url = tc.url(archive)
			}

			got := runInstaller(t, installDir, url, tc.version, tc.digest(realDigest))

			if got.exitCode != 1 {
				t.Errorf("exit=%d, want 1\n%s", got.exitCode, got.output)
			}
			if got.installed {
				t.Error("a binary was installed despite the failure")
			}
			if tc.wantMessage != "" && !strings.Contains(got.output, tc.wantMessage) {
				t.Errorf("output does not explain the failure (want %q):\n%s", tc.wantMessage, got.output)
			}
		})
	}
}

// TestInstallSyft_RequiresInstallDir covers the remaining argument contract.
//
// @spec system-supply-chain
// @ac AC-07
func TestInstallSyft_RequiresInstallDir(t *testing.T) {
	t.Log("// @spec system-supply-chain")
	t.Log("// @ac AC-07")
	requireLinuxTools(t)

	script := filepath.Join(repoRoot(t), "scripts", "install-syft.sh")
	cmd := exec.Command("bash", script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SYFT_VERSION=" + fixtureVersion, "SYFT_SHA256=deadbeef"}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("installer succeeded with no install directory:\n%s", out)
	}
}
