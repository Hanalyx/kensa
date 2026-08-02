package filepermissions_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/handlers/filepermissions"
	"github.com/Hanalyx/kensa/internal/transcript"
)

// transcriptDir is the recorded-output tree, relative to this package.
const transcriptDir = "../../transcript/testdata/transcripts"

// TestCaptureAgainstRecordedOutput runs Capture against command output
// recorded from real hosts instead of a fixture written by hand.
//
// The hand-written fixture in this package asserts that /etc/shadow is mode
// 0644, owned root:root, with SELinux type etc_t. None of that is true on any
// host in the fleet: RHEL 9 and RHEL 10 report mode 0 with shadow_t, and
// Ubuntu 24 reports 640 root:shadow with no SELinux context at all. The
// fixture still passes, because a parser exercised with invented input proves
// only that it parses invented input.
//
// What the recording adds is divergence the author did not think of. Across
// three transcripts the same command returns a different mode, a different
// group, a different gid, and SELinux present or absent. A parser that
// silently shifted a field would produce plausible output on one of those and
// wrong output on the others.
//
// Expectations are DERIVED from the recorded bytes by a second, deliberately
// naive parse rather than typed in. Two independent readings of the same real
// output must agree; a hand-typed expectation would just be the fixture
// problem in a new place.
//
// @spec test-recorded-transcripts
// @ac AC-05
func TestCaptureAgainstRecordedOutput(t *testing.T) {
	t.Run("test-recorded-transcripts/AC-05", func(t *testing.T) {})

	transcripts, err := transcript.LoadDir(transcriptDir)
	if err != nil {
		t.Fatalf("load transcripts: %v", err)
	}
	if len(transcripts) == 0 {
		t.Fatal("no transcripts recorded; run cmd/kensa-transcript against a fleet host")
	}

	const path = "/etc/shadow"
	cmd := "stat -c '%a|%U|%u|%G|%g' '" + path + "' && ls -Zd '" + path + "' 2>/dev/null | awk '{print $1}'"

	for osKey, tr := range transcripts {
		t.Run(osKey, func(t *testing.T) {
			entry, ok := tr.Lookup(cmd)
			if !ok {
				t.Skipf("%s transcript has no recording for the single-target capture command", osKey)
			}

			pre, err := filepermissions.New().Capture(
				context.Background(),
				transcript.NewTransport(t, tr),
				api.Params{"path": path},
			)
			if err != nil {
				t.Fatalf("Capture on recorded %s output: %v", osKey, err)
			}

			// Second, naive reading of the same recorded bytes.
			wantMode, wantOwner, wantUID, wantGroup, wantGID, wantSELinux := naiveParse(t, entry.Stdout)

			for _, c := range []struct{ key, want string }{
				{"path", path},
				{"owner", wantOwner},
				{"uid", wantUID},
				{"group", wantGroup},
				{"gid", wantGID},
				{"selinux_context", wantSELinux},
			} {
				if got, _ := pre.Data[c.key].(string); got != c.want {
					t.Errorf("Data[%q] = %q, want %q (from the recorded %s output)", c.key, got, c.want, osKey)
				}
			}

			// The handler zero-pads the mode; compare on the numeric value so
			// the assertion does not encode a formatting choice.
			gotMode, _ := pre.Data["mode"].(string)
			if strings.TrimLeft(gotMode, "0") != strings.TrimLeft(wantMode, "0") {
				t.Errorf("Data[mode] = %q, want the recorded mode %q", gotMode, wantMode)
			}

			t.Logf("%s: %s is mode %s %s:%s selinux=%s", osKey, path, gotMode, wantOwner, wantGroup, wantSELinux)
		})
	}
}

// TestRecordedOutputDivergesAcrossPlatforms asserts the recordings actually
// disagree with each other.
//
// The value of a transcript is that it carries platform divergence a fixture
// author would not invent. If every recording were identical, the suite would
// be a fixture with extra steps. /etc/shadow is the clearest case: RHEL keeps
// it root-owned and unreadable with an SELinux label, Debian and Ubuntu give
// it group shadow and no label.
//
// @spec test-recorded-transcripts
// @ac AC-05
func TestRecordedOutputDivergesAcrossPlatforms(t *testing.T) {
	t.Run("test-recorded-transcripts/AC-05", func(t *testing.T) {})

	transcripts, err := transcript.LoadDir(transcriptDir)
	if err != nil {
		t.Fatalf("load transcripts: %v", err)
	}
	if len(transcripts) < 2 {
		t.Skip("need at least two recorded platforms to compare")
	}

	const path = "/etc/shadow"
	cmd := "stat -c '%a|%U|%u|%G|%g' '" + path + "' && ls -Zd '" + path + "' 2>/dev/null | awk '{print $1}'"

	seen := map[string]string{}
	selinuxPresent, selinuxAbsent := 0, 0
	for osKey, tr := range transcripts {
		entry, ok := tr.Lookup(cmd)
		if !ok {
			continue
		}
		seen[osKey] = entry.Stdout
		if strings.TrimSpace(lastLine(entry.Stdout)) == "?" {
			selinuxAbsent++
		} else {
			selinuxPresent++
		}
	}
	if len(seen) < 2 {
		t.Skip("fewer than two transcripts recorded this command")
	}

	distinct := map[string]bool{}
	for _, out := range seen {
		distinct[out] = true
	}
	if len(distinct) == 1 {
		t.Errorf("every recorded platform returned identical output for %s:\n  %q\n"+
			"Either the transcripts were captured from one host, or this command carries no "+
			"platform divergence and is a weak choice for a cross-platform recording.", path, lastOf(seen))
	}
	if selinuxPresent == 0 || selinuxAbsent == 0 {
		t.Logf("SELinux divergence not represented (present on %d, absent on %d); "+
			"record an SELinux-less platform to cover the '?' path", selinuxPresent, selinuxAbsent)
	}
}

// naiveParse reads the recorded stat+ls output independently of the handler.
func naiveParse(t *testing.T, stdout string) (mode, owner, uid, group, gid, selinux string) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) < 1 {
		t.Fatalf("recorded stdout has no lines: %q", stdout)
	}
	fields := strings.Split(lines[0], "|")
	if len(fields) != 5 {
		t.Fatalf("recorded stat line has %d fields, want 5: %q", len(fields), lines[0])
	}
	selinux = ""
	if len(lines) > 1 {
		selinux = strings.TrimSpace(lines[len(lines)-1])
	}
	if selinux == "?" {
		selinux = ""
	}
	return fields[0], fields[1], fields[2], fields[3], fields[4], selinux
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

func lastOf(m map[string]string) string {
	for _, v := range m {
		return v
	}
	return ""
}
