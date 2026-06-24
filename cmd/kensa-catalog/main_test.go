package main

import (
	"bytes"
	"strings"
	"testing"
)

// @spec catalog-coverage-crosswalk
// @ac AC-08
func TestRun_Help(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-08", func(t *testing.T) {
		// --help, -h, and the help subcommand print full usage to stdout, exit 0.
		for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
			var out, errb bytes.Buffer
			if code := run(args, &out, &errb); code != 0 {
				t.Errorf("run(%v) exit = %d, want 0 (stderr: %s)", args, code, errb.String())
			}
			got := out.String()
			for _, want := range []string{"kensa-catalog", "coverage", "missing", "drift"} {
				if !strings.Contains(got, want) {
					t.Errorf("run(%v) usage missing %q; got:\n%s", args, want, got)
				}
			}
		}

		// No arguments is a usage error: exit 2.
		var out, errb bytes.Buffer
		if code := run(nil, &out, &errb); code != 2 {
			t.Errorf("run(nil) exit = %d, want 2", code)
		}

		// An unknown command is a usage error reported on stderr: exit 2.
		out.Reset()
		errb.Reset()
		if code := run([]string{"bogus"}, &out, &errb); code != 2 {
			t.Errorf("run([bogus]) exit = %d, want 2", code)
		}
		if !strings.Contains(errb.String(), "unknown command") {
			t.Errorf("unknown command should be reported on stderr; got: %s", errb.String())
		}
	})
}
