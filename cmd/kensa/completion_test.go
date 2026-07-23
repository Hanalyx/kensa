package main

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

var flagRE = regexp.MustCompile(`--[a-z][a-z0-9-]+`)

// flagsFromHelp extracts the sorted, de-duplicated set of long flags a command
// advertises in its `--help` output.
func flagsFromHelp(t *testing.T, cmd string) []string {
	t.Helper()
	stdout, stderr := captureRunCLI([]string{cmd, "--help"}, t)
	seen := map[string]bool{}
	for _, m := range flagRE.FindAllString(stdout+"\n"+stderr, -1) {
		seen[strings.TrimPrefix(m, "--")] = true
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// TestCompletion_NoFlagDrift is the drift-guard: every flag a command actually
// advertises via --help MUST appear in its completionSpec, and vice-versa. This
// fails the build if a flag is added to a command without updating the table,
// so `kensa completion` can never silently omit a real flag. The `completion`
// command itself is exempt (it is not pflag-driven; its --help lists no flags).
func TestCompletion_NoFlagDrift(t *testing.T) {
	for _, spec := range completionSpecs {
		if spec.name == "completion" {
			continue
		}
		t.Run(spec.name, func(t *testing.T) {
			want := append([]string(nil), spec.flags...)
			sort.Strings(want)
			got := flagsFromHelp(t, spec.name)
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("completion flag drift for %q:\n  --help advertises: %v\n  completionSpec has: %v\n  update completionSpecs in completion.go",
					spec.name, got, want)
			}
		})
	}
}

// TestCompletion_CoversAllDispatchCommands asserts every command reachable from
// the CLI dispatch is present in completionSpecs — so a newly-added command is
// not silently left out of completion. The list mirrors the runCLI switch.
func TestCompletion_CoversAllDispatchCommands(t *testing.T) {
	dispatch := []string{
		"detect", "check", "remediate", "rollback", "recover", "history",
		"plan", "mechanisms", "coverage", "list", "info", "diff", "agent",
		"verify", "migrate", "version", "completion",
	}
	have := map[string]bool{}
	for _, s := range completionSpecs {
		have[s.name] = true
	}
	for _, c := range dispatch {
		if !have[c] {
			t.Errorf("dispatch command %q is missing from completionSpecs", c)
		}
	}
	if len(completionSpecs) != len(dispatch) {
		t.Errorf("completionSpecs has %d entries; dispatch has %d — keep them in sync",
			len(completionSpecs), len(dispatch))
	}
}

// TestCompletion_ShellScripts checks each shell generator emits a plausible,
// non-empty script that names every subcommand.
func TestCompletion_ShellScripts(t *testing.T) {
	cases := []struct {
		shell  string
		script string
		marker string
	}{
		{"bash", bashCompletion(), "complete -F _kensa kensa"},
		{"zsh", zshCompletion(), "#compdef kensa"},
		{"fish", fishCompletion(), "complete -c kensa"},
	}
	for _, tc := range cases {
		t.Run(tc.shell, func(t *testing.T) {
			if !strings.Contains(tc.script, tc.marker) {
				t.Errorf("%s script missing marker %q", tc.shell, tc.marker)
			}
			for _, s := range completionSpecs {
				if !strings.Contains(tc.script, s.name) {
					t.Errorf("%s script does not mention command %q", tc.shell, s.name)
				}
				for _, f := range s.flags {
					if !strings.Contains(tc.script, "--"+f) && !strings.Contains(tc.script, "-l "+f) {
						t.Errorf("%s script missing flag --%s for command %s", tc.shell, f, s.name)
					}
				}
			}
		})
	}
}

// TestCompletion_Dispatch checks the subcommand end-to-end via runCLI: a valid
// shell emits its script to stdout (exit 0); a bad shell is a usage error.
func TestCompletion_Dispatch(t *testing.T) {
	for _, shell := range supportedShells {
		stdout, _ := captureRunCLI([]string{"completion", shell}, t)
		if !strings.Contains(stdout, "kensa") {
			t.Errorf("completion %s produced no script", shell)
		}
	}
	_, stderr := captureRunCLI([]string{"completion", "tcsh"}, t)
	if !strings.Contains(stderr, "unsupported shell") {
		t.Errorf("completion with a bad shell should be a usage error; stderr=%q", stderr)
	}
	_, stderr = captureRunCLI([]string{"completion"}, t)
	if !strings.Contains(stderr, "specify a shell") {
		t.Errorf("bare completion should ask for a shell; stderr=%q", stderr)
	}
}
