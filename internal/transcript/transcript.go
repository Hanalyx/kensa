// Package transcript replays command output recorded from a real host.
//
// # Why this exists
//
// A test fake is written from the author's belief about what a command
// prints. When that belief is wrong, the fake agrees with the code, every
// gate passes, and the defect ships. Three separate defects reached
// production this way:
//
//   - The service handlers read `systemctl show -p UnitFileState -p
//     ActiveState --value` positionally. systemd prints ActiveState first.
//     The fixture returned "enabled\nactive\n", the order the code asked
//     for, so capture stored the two values under each other's keys for 23
//     releases while every test passed.
//   - The deadman scheduler emitted `at now + N seconds`, which at(1) cannot
//     parse. The fake returned a job line for any time spec, so the spec,
//     the code and the fixture agreed on a syntax no host accepts.
//   - A rollback test asserted `enable --now` for a unit captured as
//     stopped, encoding an over-restore as the expected behavior.
//
// The common factor is not carelessness. It is that a fixture and the code
// it checks come from the same understanding, so the fixture cannot
// contradict the code. A recording can, because it comes from the system.
//
// # What a transcript is
//
// A transcript is command output captured from a real host once, checked in,
// and replayed in tests: the exact command, its stdout, stderr, exit code,
// and which OS produced it. Tests that replay a transcript assert against
// what the system does rather than what the author expected.
//
// # Strictness
//
// [Transport] fails the test on a command the transcript does not contain,
// rather than returning success. This is the property that makes a
// transcript trustworthy: if a handler changes the command it issues, the
// replay stops matching and the test fails loudly, instead of silently
// exercising nothing. engine.FakeTransport returns exit 0 with empty output
// for any unrecognized command, which is how a fixture can drift away from
// the code under test and still report a pass.
package transcript

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// Entry is one recorded command and its result.
type Entry struct {
	// Command is the exact command string issued to the transport.
	Command string `json:"command"`
	// Stdout, Stderr and ExitCode are what the host returned, verbatim.
	// Stdout retains the trailing newline the transport delivered, if any:
	// a trimmed recording would reintroduce the class of defect this
	// package exists to prevent.
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	// Note records why this command is in the transcript when the reason
	// is not obvious. Optional.
	Note string `json:"note,omitempty"`
}

// Transcript is a set of recorded commands from one host.
type Transcript struct {
	// OS identifies the recorded platform, for example "rhel9" or
	// "ubuntu24". Transcripts are per-OS because the same command prints
	// differently across them, which is the point.
	OS string `json:"os"`
	// OSRelease is the host's /etc/os-release PRETTY_NAME at capture time.
	OSRelease string `json:"os_release,omitempty"`
	// Systemd is the systemd version string, when relevant to the commands
	// recorded. Property ordering and flag support vary by version.
	Systemd string `json:"systemd,omitempty"`
	// CapturedAt is the ISO 8601 date of capture. A transcript does not
	// expire, but a reader deciding whether to re-record needs the date.
	CapturedAt string `json:"captured_at"`
	// Entries are the recorded commands.
	Entries []Entry `json:"entries"`
}

// Load reads a transcript from path.
func Load(path string) (*Transcript, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("transcript: read %s: %w", path, err)
	}
	var t Transcript
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("transcript: parse %s: %w", path, err)
	}
	if t.OS == "" {
		return nil, fmt.Errorf("transcript: %s has no os field", path)
	}
	return &t, nil
}

// LoadDir reads every transcript under dir, keyed by OS.
func LoadDir(dir string) (map[string]*Transcript, error) {
	out := map[string]*Transcript{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		t, lerr := Load(path)
		if lerr != nil {
			return lerr
		}
		if prev, dup := out[t.OS]; dup {
			return fmt.Errorf("transcript: two transcripts claim os %q (%s and %s)", t.OS, prev.OSRelease, path)
		}
		out[t.OS] = t
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Save writes t to path, creating parent directories.
func Save(path string, t *Transcript) error {
	sort.Slice(t.Entries, func(i, j int) bool { return t.Entries[i].Command < t.Entries[j].Command })
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("transcript: mkdir for %s: %w", path, err)
	}
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return fmt.Errorf("transcript: encode %s: %w", path, err)
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Lookup returns the recorded entry for cmd.
func (t *Transcript) Lookup(cmd string) (Entry, bool) {
	for _, e := range t.Entries {
		if e.Command == cmd {
			return e, true
		}
	}
	return Entry{}, false
}

// Commands returns every recorded command, sorted.
func (t *Transcript) Commands() []string {
	out := make([]string, 0, len(t.Entries))
	for _, e := range t.Entries {
		out = append(out, e.Command)
	}
	sort.Strings(out)
	return out
}

// TestingT is the subset of *testing.T this package needs, so the transport
// can fail a test without importing the testing package into non-test code.
type TestingT interface {
	Helper()
	Fatalf(format string, args ...any)
}

// Transport replays a transcript as an [api.Transport].
//
// A command the transcript does not contain FAILS THE TEST. That is the
// whole design: a permissive fake lets a handler's command drift away from
// its fixture while the test keeps passing, which is how three defects
// reached production. A strict replay converts that drift into a failure at
// the moment it happens, and names both the command it saw and the commands
// it has.
type Transport struct {
	t  TestingT
	tr *Transcript
	// Runs records every command issued, in order, so a test can assert on
	// what the code actually did.
	Runs []string
}

// NewTransport returns a Transport replaying tr and failing t on any
// command tr does not contain.
func NewTransport(t TestingT, tr *Transcript) *Transport {
	return &Transport{t: t, tr: tr}
}

// Run replays the recorded result for cmd, or fails the test.
func (r *Transport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	r.t.Helper()
	r.Runs = append(r.Runs, cmd)

	entry, ok := r.tr.Lookup(cmd)
	if !ok {
		r.t.Fatalf(
			"transcript(%s): no recording for command\n  issued:   %q\n  recorded: %s\n"+
				"The code under test issues a command this transcript does not contain. Either the "+
				"command changed and the transcript needs re-recording against a real host, or the "+
				"test is exercising a path this transcript was not captured for. Do NOT add the "+
				"command by hand: a hand-written entry is the fixture problem this package exists "+
				"to remove.",
			r.tr.OS, cmd, formatCommands(r.tr.Commands()))
		return nil, fmt.Errorf("transcript: no recording for %q", cmd)
	}

	return &api.CommandResult{
		Stdout:   entry.Stdout,
		Stderr:   entry.Stderr,
		ExitCode: entry.ExitCode,
	}, nil
}

// Put is a no-op for replay.
func (r *Transport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }

// Get is a no-op for replay.
func (r *Transport) Get(_ context.Context, _, _ string) error { return nil }

// Close is a no-op for replay.
func (r *Transport) Close() error { return nil }

// ControlChannelSensitive reports false: a replay cannot lose a channel.
func (r *Transport) ControlChannelSensitive() bool { return false }

func formatCommands(cmds []string) string {
	if len(cmds) == 0 {
		return "(none)"
	}
	var b strings.Builder
	for _, c := range cmds {
		b.WriteString("\n    ")
		b.WriteString(c)
	}
	return b.String()
}
