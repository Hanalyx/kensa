package transcript_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/transcript"
)

// fakeT captures a Fatalf instead of aborting, so a test can assert that the
// transport fails rather than merely observing that it did.
type fakeT struct {
	failed bool
	msg    string
}

func (f *fakeT) Helper() {}
func (f *fakeT) Fatalf(format string, args ...any) {
	f.failed = true
	f.msg = strings.TrimSpace(fmt.Sprintf(format, args...))
}

// TestTransportFailsOnUnrecordedCommand is the property the whole package
// rests on.
//
// engine.FakeTransport answers exit 0 with empty output for any command it was
// not programmed for. That is why a fixture can drift away from the code it
// checks and the test still passes: the handler issues a command nobody
// recorded, receives a plausible success, and the assertions downstream
// examine whatever the handler makes of nothing. Three shipped defects took
// that route.
//
// A replay must do the opposite. An unrecorded command is not a silent
// success; it is the test telling you it no longer exercises what it claims.
//
// @spec test-recorded-transcripts
// @ac AC-01
func TestTransportFailsOnUnrecordedCommand(t *testing.T) {
	t.Run("test-recorded-transcripts/AC-01", func(t *testing.T) {})

	tr := &transcript.Transcript{
		OS:      "testos",
		Entries: []transcript.Entry{{Command: "recorded-command", Stdout: "output"}},
	}

	ft := &fakeT{}
	rt := transcript.NewTransport(ft, tr)
	if _, err := rt.Run(context.Background(), "a-command-nobody-recorded"); err == nil {
		t.Error("replaying an unrecorded command returned no error")
	}
	if !ft.failed {
		t.Fatal("replaying an unrecorded command did not fail the test; a permissive replay is a fixture")
	}
	for _, want := range []string{"a-command-nobody-recorded", "recorded-command", "re-recording"} {
		if !strings.Contains(ft.msg, want) {
			t.Errorf("failure message does not mention %q, so it does not tell the reader what to do:\n%s", want, ft.msg)
		}
	}
}

// TestTransportReplaysVerbatim covers the detail that made the file_content
// rollback defect possible: transports trim, and a recording that trims too
// reintroduces the divergence it exists to remove.
//
// @spec test-recorded-transcripts
// @ac AC-02
func TestTransportReplaysVerbatim(t *testing.T) {
	t.Run("test-recorded-transcripts/AC-02", func(t *testing.T) {})

	want := transcript.Entry{
		Command:  "some-command",
		Stdout:   "line one\nline two\n",
		Stderr:   "a warning\n",
		ExitCode: 3,
	}
	rt := transcript.NewTransport(t, &transcript.Transcript{OS: "testos", Entries: []transcript.Entry{want}})

	got, err := rt.Run(context.Background(), "some-command")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Stdout != want.Stdout {
		t.Errorf("stdout = %q, want %q verbatim including the trailing newline", got.Stdout, want.Stdout)
	}
	if got.Stderr != want.Stderr {
		t.Errorf("stderr = %q, want %q", got.Stderr, want.Stderr)
	}
	if got.ExitCode != want.ExitCode {
		t.Errorf("exit = %d, want %d", got.ExitCode, want.ExitCode)
	}
	if len(rt.Runs) != 1 || rt.Runs[0] != "some-command" {
		t.Errorf("Runs = %v, want the issued command recorded", rt.Runs)
	}
}

// TestRecordedTranscriptsCoverTheManifest keeps the manifest and the
// recordings from drifting apart.
//
// A command added to the manifest and never recorded is a command no test can
// replay, and the failure would otherwise appear later as a confusing
// unrecorded-command error in an unrelated package.
//
// @spec test-recorded-transcripts
// @ac AC-03
func TestRecordedTranscriptsCoverTheManifest(t *testing.T) {
	t.Run("test-recorded-transcripts/AC-03", func(t *testing.T) {})

	type manifestEntry struct {
		Command string   `json:"command"`
		OnlyOn  []string `json:"only_on"`
	}
	data, err := os.ReadFile(filepath.Join("testdata", "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest []manifestEntry
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}

	transcripts, err := transcript.LoadDir(filepath.Join("testdata", "transcripts"))
	if err != nil {
		t.Fatalf("load transcripts: %v", err)
	}
	if len(transcripts) == 0 {
		t.Fatal("no transcripts recorded")
	}

	for osKey, tr := range transcripts {
		for _, m := range manifest {
			if len(m.OnlyOn) > 0 && !contains(m.OnlyOn, osKey) {
				continue
			}
			if _, ok := tr.Lookup(m.Command); !ok {
				t.Errorf("%s transcript is missing a manifest command:\n  %s\n"+
					"Re-record it: go run ./cmd/kensa-transcript -host <host> -user <user> -os %s -sudo",
					osKey, m.Command, osKey)
			}
		}
	}
}

// TestTranscriptsCarryTheirProvenance: a recording that cannot say which
// system produced it, and when, is a fixture with extra ceremony.
//
// @spec test-recorded-transcripts
// @ac AC-04
func TestTranscriptsCarryTheirProvenance(t *testing.T) {
	t.Run("test-recorded-transcripts/AC-04", func(t *testing.T) {})

	transcripts, err := transcript.LoadDir(filepath.Join("testdata", "transcripts"))
	if err != nil {
		t.Fatalf("load transcripts: %v", err)
	}
	for osKey, tr := range transcripts {
		if tr.OSRelease == "" {
			t.Errorf("%s transcript records no OSRelease", osKey)
		}
		if tr.CapturedAt == "" {
			t.Errorf("%s transcript records no capture date", osKey)
		}
		if len(tr.Entries) == 0 {
			t.Errorf("%s transcript has no entries", osKey)
		}
	}
}

// TestSaveLoadRoundTrip guards the encoding, including the trailing newlines
// a naive round trip would eat.
//
// @spec test-recorded-transcripts
// @ac AC-02
func TestSaveLoadRoundTrip(t *testing.T) {
	t.Run("test-recorded-transcripts/AC-02", func(t *testing.T) {})

	in := &transcript.Transcript{
		OS: "testos", OSRelease: "Test Linux 1.0", CapturedAt: "2026-08-02",
		Entries: []transcript.Entry{
			{Command: "b", Stdout: "trailing\n", ExitCode: 0},
			{Command: "a", Stdout: "no trailing", Stderr: "err\n", ExitCode: 1},
		},
	}
	path := filepath.Join(t.TempDir(), "testos.json")
	if err := transcript.Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := transcript.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, want := range in.Entries {
		got, ok := out.Lookup(want.Command)
		if !ok {
			t.Errorf("entry %q lost in round trip", want.Command)
			continue
		}
		if got != want {
			t.Errorf("entry %q changed in round trip:\n got  %+v\n want %+v", want.Command, got, want)
		}
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
