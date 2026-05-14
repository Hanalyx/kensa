package detect

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// osTestTransport is a minimal Transport for unit tests that intercepts
// the os-release Run call. Real SSH paths are exercised in the
// detect_test.go integration tests.
type osTestTransport struct {
	stdout   string
	exitCode int
	err      error
}

func (f *osTestTransport) Run(_ context.Context, _ string) (*api.CommandResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &api.CommandResult{
		Stdout:   f.stdout,
		ExitCode: f.exitCode,
	}, nil
}

func (f *osTestTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error {
	return nil
}
func (f *osTestTransport) Get(_ context.Context, _, _ string) error { return nil }
func (f *osTestTransport) ControlChannelSensitive() bool            { return false }
func (f *osTestTransport) Close() error                             { return nil }

func TestParseOSRelease_RHEL(t *testing.T) {
	content := `NAME="Red Hat Enterprise Linux"
VERSION="9.6 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.6"
PRETTY_NAME="Red Hat Enterprise Linux 9.6 (Plow)"`
	info := parseOSRelease(content)
	if info.Family != "rhel" {
		t.Errorf("Family = %q, want rhel", info.Family)
	}
	if info.Version != "9.6" {
		t.Errorf("Version = %q, want 9.6", info.Version)
	}
	if info.PrettyName != "Red Hat Enterprise Linux 9.6 (Plow)" {
		t.Errorf("PrettyName = %q", info.PrettyName)
	}
}

func TestParseOSRelease_Ubuntu(t *testing.T) {
	content := `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"`
	info := parseOSRelease(content)
	if info.Family != "ubuntu" {
		t.Errorf("Family = %q, want ubuntu", info.Family)
	}
	if info.Version != "22.04" {
		t.Errorf("Version = %q, want 22.04", info.Version)
	}
}

func TestParseOSRelease_SingleQuotes(t *testing.T) {
	// os-release(5) allows single-quoted values too.
	content := `ID='alpine'
VERSION_ID='3.18'`
	info := parseOSRelease(content)
	if info.Family != "alpine" {
		t.Errorf("Family = %q, want alpine", info.Family)
	}
	if info.Version != "3.18" {
		t.Errorf("Version = %q, want 3.18", info.Version)
	}
}

func TestParseOSRelease_NoQuotes(t *testing.T) {
	// Some minimal images (Alpine) ship unquoted values.
	content := `ID=alpine
VERSION_ID=3.19`
	info := parseOSRelease(content)
	if info.Family != "alpine" || info.Version != "3.19" {
		t.Errorf("got %+v, want {alpine, 3.19}", info)
	}
}

func TestParseOSRelease_EmptyAndComments(t *testing.T) {
	content := `# This is a comment
NAME=Linux

ID=foo
VERSION_ID=1.0`
	info := parseOSRelease(content)
	if info.Family != "foo" || info.Version != "1.0" {
		t.Errorf("got %+v", info)
	}
}

func TestParseOSRelease_MissingFile_EmptyContent(t *testing.T) {
	if got := parseOSRelease(""); got.Family != "" || got.Version != "" {
		t.Errorf("empty content should produce zero OSInfo; got %+v", got)
	}
}

func TestParseOSRelease_MalformedLine(t *testing.T) {
	// Lines without '=' should be ignored, not crash.
	content := `ID=foo
malformed line without equals
VERSION_ID=1.0`
	info := parseOSRelease(content)
	if info.Family != "foo" || info.Version != "1.0" {
		t.Errorf("got %+v", info)
	}
}

func TestOSInfo_Label(t *testing.T) {
	tests := []struct {
		name string
		in   OSInfo
		want string
	}{
		{"rhel", OSInfo{Family: "rhel", Version: "9.6"}, "RHEL 9.6"},
		{"ubuntu", OSInfo{Family: "ubuntu", Version: "22.04"}, "Ubuntu 22.04"},
		{"fedora-no-version", OSInfo{Family: "fedora"}, "Fedora"},
		{"empty", OSInfo{}, ""},
		{"unknown-family", OSInfo{Family: "novel-distro", Version: "1.0"}, "NOVEL-DISTRO 1.0"},
		{"version-only", OSInfo{Version: "1.0"}, "1.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Label(); got != tc.want {
				t.Errorf("Label() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDetectOS_HappyPath(t *testing.T) {
	tx := &osTestTransport{
		stdout: `ID=rhel
VERSION_ID="9.6"`,
		exitCode: 0,
	}
	info, err := DetectOS(context.Background(), tx)
	if err != nil {
		t.Fatalf("DetectOS: %v", err)
	}
	if info.Label() != "RHEL 9.6" {
		t.Errorf("Label() = %q, want RHEL 9.6", info.Label())
	}
}

func TestDetectOS_MissingFile(t *testing.T) {
	// Some minimal hosts (containers, RHEL 6) don't have
	// /etc/os-release. Run exits non-zero. DetectOS returns a zero
	// OSInfo without erroring; the host banner falls back.
	tx := &osTestTransport{exitCode: 1}
	info, err := DetectOS(context.Background(), tx)
	if err != nil {
		t.Errorf("missing file should not produce an error: %v", err)
	}
	if info.Label() != "" {
		t.Errorf("missing file should produce zero OSInfo; got Label %q", info.Label())
	}
}

func TestDetectOS_TransportError(t *testing.T) {
	// Network/transport failures DO surface as errors so callers
	// can retry or fall through.
	tx := &osTestTransport{err: errors.New("ssh closed")}
	_, err := DetectOS(context.Background(), tx)
	if err == nil {
		t.Error("transport error should surface")
	}
}
