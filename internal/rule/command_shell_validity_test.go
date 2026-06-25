package rule

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// commandRunScripts returns every shell script carried by a command-method
// check in the rule, recursing into composed sub-checks.
func commandRunScripts(c api.Check) []string {
	var out []string
	if c.Method == "command" {
		if run, ok := c.Params["run"].(string); ok && strings.TrimSpace(run) != "" {
			out = append(out, run)
		}
	}
	for _, sub := range c.Checks {
		out = append(out, commandRunScripts(sub)...)
	}
	return out
}

// TestCorpusCommandChecksAreShellValid is the corpus gate against silently
// broken command checks: a YAML folded scalar that collapses `fi` into the
// next statement, or a bashism that breaks under dash. Kensa runs check
// scripts via the target host's /bin/sh (dash on Debian/Ubuntu, bash on
// RHEL), so every script must be valid POSIX shell. On the CI runner /bin/sh
// is dash, making `sh -n` the strict baseline.
//
// @spec rule-command-shell-validity
// @ac AC-01
func TestCorpusCommandChecksAreShellValid(t *testing.T) {
	t.Run("rule-command-shell-validity/AC-01", func(t *testing.T) {
		sh, err := exec.LookPath("sh")
		if err != nil {
			t.Skip("no POSIX sh available to validate command scripts")
		}
		for id, r := range loadCorpus(t) {
			for _, impl := range r.Implementations {
				for _, script := range commandRunScripts(impl.Check) {
					cmd := exec.Command(sh, "-n")
					cmd.Stdin = strings.NewReader(script)
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Errorf("%s: command check script is not valid POSIX shell: %v\n%s\n--- script ---\n%s",
							id, err, strings.TrimSpace(string(out)), script)
					}
				}
			}
		}
	})
}
