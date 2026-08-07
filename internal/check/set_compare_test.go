package check

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

type setStub struct {
	api.Transport
	stdout string
	exit   int
	gotCmd string
}

func (s *setStub) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	s.gotCmd = cmd
	return &api.CommandResult{Stdout: s.stdout, ExitCode: s.exit}, nil
}

func TestSetCompare(t *testing.T) {
	for _, tc := range []struct {
		name       string
		observed   string
		exit       int
		authorized string
		pass       bool
		wantDetail string
		wantErr    string
	}{
		{
			name:     "every observed member is authorized",
			observed: "alice\nbob\n", authorized: "alice,bob,carol", pass: true,
			wantDetail: "declared but absent: carol",
		},
		{
			name:     "an unauthorized member fails and is named",
			observed: "alice\nbob\nmallory\n", authorized: "alice,bob",
			pass: false, wantDetail: "present but not authorized: mallory",
		},
		{
			name:     "nothing observed passes; an empty host cannot be non-compliant",
			observed: "", authorized: "alice", pass: true,
		},
		{
			// The false-pass this whole area exists to avoid: an undeclared or
			// empty set must never mark a host compliant.
			name:     "empty authorized set is an error, never a pass",
			observed: "alice\n", authorized: "", wantErr: "nothing to compare against",
		},
		{
			name:     "whitespace-only authorized set is also an error",
			observed: "alice\n", authorized: "  ,  ", wantErr: "nothing to compare against",
		},
		{
			name:     "a failing observer is an error, not a verdict",
			observed: "", exit: 2, authorized: "alice", wantErr: "unknown",
		},
		{
			name:     "duplicates and blank lines do not change the answer",
			observed: "alice\n\nalice\n  bob  \n", authorized: "bob,alice,alice", pass: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &setStub{stdout: tc.observed, exit: tc.exit}
			pass, detail, err := checkSetCompare(context.Background(), st,
				api.Params{"observed_command": "getent passwd", "authorized": tc.authorized})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got pass=%v detail=%q err=%v", tc.wantErr, pass, detail, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pass != tc.pass {
				t.Errorf("pass = %v, want %v (detail: %s)", pass, tc.pass, detail)
			}
			if tc.wantDetail != "" && !strings.Contains(detail, tc.wantDetail) {
				t.Errorf("detail %q does not contain %q", detail, tc.wantDetail)
			}
		})
	}
}

// Missing params must be a usage error rather than a silent verdict.
func TestSetCompareRequiresBothParams(t *testing.T) {
	for _, p := range []api.Params{
		{"authorized": "alice"},
		{"observed_command": "true"},
	} {
		if _, _, err := checkSetCompare(context.Background(), &setStub{}, p); err == nil {
			t.Errorf("params %v: want a usage error, got nil", p)
		}
	}
}

// An empty declared set must be reported as NOT ASSESSABLE, which the scan maps
// to skipped. It must never be a pass, and it must not be an error either: a
// fleet that has not written its policy yet is a normal state, not a fault.
func TestSetCompareEmptyIsNotAssessableNotError(t *testing.T) {
	_, _, err := checkSetCompare(context.Background(), &setStub{stdout: "alice\n"},
		api.Params{"observed_command": "x", "authorized": ""})
	if err == nil {
		t.Fatal("want an error value carrying the sentinel")
	}
	if !errors.Is(err, ErrNotAssessable) {
		t.Errorf("want ErrNotAssessable so the scan records a skip, got %v", err)
	}
}

// A site may authorize an account by user name or by numeric UID. Both name the
// SAME account, so neither may be reported as an unauthorized extra.
func TestSetCompareMatchesAnAlias(t *testing.T) {
	const observed = "owadmin:1000\ndeploybot:1001\n"
	for _, tc := range []struct {
		name       string
		authorized string
		pass       bool
		want       string
	}{
		{name: "both declared by name", authorized: "owadmin,deploybot", pass: true},
		{name: "declared by UID", authorized: "1000,1001", pass: true},
		{name: "mixed name and UID", authorized: "owadmin,1001", pass: true},
		{name: "one account undeclared", authorized: "owadmin", pass: false, want: "deploybot"},
		{name: "undeclared, reported by name not UID", authorized: "1000", pass: false, want: "deploybot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pass, detail, err := checkSetCompare(context.Background(), &setStub{stdout: observed},
				api.Params{"observed_command": "x", "authorized": tc.authorized, "alias_separator": ":"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pass != tc.pass {
				t.Errorf("pass = %v, want %v (%s)", pass, tc.pass, detail)
			}
			if tc.want != "" && !strings.Contains(detail, tc.want) {
				t.Errorf("detail %q should name %q", detail, tc.want)
			}
			// The UID must never be reported as an extra member.
			if pass && strings.Contains(detail, "not authorized") {
				t.Errorf("a matched alias was reported as unauthorized: %s", detail)
			}
		})
	}
}
