package check

import (
	"context"
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
