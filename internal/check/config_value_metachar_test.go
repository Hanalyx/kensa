package check

import (
	"context"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// grepRegexTransport evaluates the actual `grep -E` pattern the check builds
// against simulated file content, using Go's regexp as a stand-in for ERE.
// Unlike lineTransport (which returns the line for ANY grep), this exercises
// real pattern matching — the only way to catch a key whose regex
// metacharacters make the pattern match nothing.
type grepRegexTransport struct{ content string }

func (g *grepRegexTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	if !strings.HasPrefix(cmd, "grep") {
		return &api.CommandResult{ExitCode: 1}, nil
	}
	i := strings.Index(cmd, "-E '")
	if i < 0 {
		return &api.CommandResult{ExitCode: 2}, nil
	}
	rest := cmd[i+4:]
	j := strings.Index(rest, "'")
	if j < 0 {
		return &api.CommandResult{ExitCode: 2}, nil
	}
	pattern := rest[:j]
	re, err := regexp.Compile(pattern)
	if err != nil {
		// A malformed pattern is grep's "exit 2" — mirrors an unescaped
		// metachar key like "* hard core" producing invalid repetition.
		return &api.CommandResult{ExitCode: 2}, nil
	}
	for _, line := range strings.Split(g.content, "\n") {
		if re.MatchString(line) {
			return &api.CommandResult{ExitCode: 0, Stdout: line + "\n"}, nil
		}
	}
	return &api.CommandResult{ExitCode: 1}, nil
}

func (g *grepRegexTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (g *grepRegexTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (g *grepRegexTransport) ControlChannelSensitive() bool                           { return false }
func (g *grepRegexTransport) Close() error                                            { return nil }

// TestConfigValueRegexMetacharKey guards the fix for keys that contain regex
// metacharacters. Before the fix, config_value spliced the key raw into the
// grep -E pattern, so "$FileCreateMode" ($ = end-anchor) and "* hard core"
// (* = quantifier) matched nothing — the check reported a present, compliant
// line as non-compliant, which under the post-apply re-check is a spurious
// rollback of a correct change. The key is now regexp.QuoteMeta'd, and the
// whitespace-delimited value extraction strips the (possibly multi-word) key
// prefix rather than assuming fields[1].
func TestConfigValueRegexMetacharKey(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		line    string
		want    string
		wantOK  bool
		comment string
	}{
		{
			name:   "rsyslog dollar-prefixed key, space-delimited",
			key:    "$FileCreateMode",
			line:   "$FileCreateMode 0640",
			want:   "0640",
			wantOK: true,
		},
		{
			name:   "limits.conf multi-word key with star, space-delimited",
			key:    "* hard core",
			line:   "* hard core 0",
			want:   "0",
			wantOK: true,
		},
		{
			name:   "dotted key matches literally, not as any-char",
			key:    "net.ipv4.tcp_syncookies",
			line:   "net.ipv4.tcp_syncookies 1",
			want:   "1",
			wantOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chk := api.Check{Method: "config_value", Params: api.Params{
				"path": "/etc/example.conf", "key": tc.key,
				"expected": tc.want, "delimiter": " ",
			}}
			passed, detail, err := runForTest(context.Background(), &grepRegexTransport{content: tc.line}, chk)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if passed != tc.wantOK {
				t.Errorf("key %q against %q: passed=%v want %v; detail=%q", tc.key, tc.line, passed, tc.wantOK, detail)
			}
		})
	}

	// Negative control: a dotted key must NOT match a line where the dot
	// stands in for a different character (proving the key is matched
	// literally, not as a regex wildcard).
	chk := api.Check{Method: "config_value", Params: api.Params{
		"path": "/etc/example.conf", "key": "a.c",
		"expected": "1", "delimiter": " ",
	}}
	passed, _, err := runForTest(context.Background(), &grepRegexTransport{content: "abc 1"}, chk)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if passed {
		t.Error("key \"a.c\" must not match line \"abc 1\" — the dot must be escaped, not treated as any-char")
	}
}
