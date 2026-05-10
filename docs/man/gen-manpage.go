// Command gen-manpage produces the kensa(1) manpage by
// concatenating a hand-written header, generated per-subcommand
// .SS subsections (sourced from `bin/kensa <cmd> --help`), and a
// hand-written footer. Output goes to stdout; the Makefile target
// redirects it to dist/kensa.1.
//
// Usage:
//
//	go run docs/man/gen-manpage.go [-bin path/to/kensa]
//
// The default kensa binary path is "bin/kensa" (assumes `make build`
// ran first). The generator subprocesses the binary rather than
// importing pflag and walking the registry — that keeps the
// manpage's flag text byte-identical to what the operator sees from
// `kensa --help`, with no risk of the two paths diverging.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// subcommands enumerates every registered kensa subcommand whose
// --help should be embedded in the manpage. The deprecated
// `coverage` alias is excluded — it points at `mechanisms`, and
// emitting both would duplicate the same flag table under different
// .SS headings, which is exactly the operator-confused-intent
// problem we caught in C-044 review.
//
// Order is operator-facing flow: probe → check → fix → query.
// Aligns with the subcommand list in printUsage at cmd/kensa/main.go.
var subcommands = []string{
	"detect",
	"check",
	"remediate",
	"rollback",
	"history",
	"plan",
	"mechanisms",
	"list",
	"info",
	"diff",
	"agent",
	"migrate",
	"version",
}

func main() {
	binPath := flag.String("bin", "bin/kensa", "path to the kensa binary")
	headerPath := flag.String("header", "docs/man/kensa.1.header.roff", "header roff path")
	footerPath := flag.String("footer", "docs/man/kensa.1.footer.roff", "footer roff path")
	flag.Parse()

	if _, err := os.Stat(*binPath); err != nil {
		fail("kensa binary not found at %s; run `make build` first", *binPath)
	}

	header, err := os.ReadFile(*headerPath)
	if err != nil {
		fail("read header: %v", err)
	}
	footer, err := os.ReadFile(*footerPath)
	if err != nil {
		fail("read footer: %v", err)
	}

	var body bytes.Buffer
	for _, cmd := range subcommands {
		section, err := genSubcommandSection(*binPath, cmd)
		if err != nil {
			fail("subcommand %q: %v", cmd, err)
		}
		body.WriteString(section)
	}

	// Concat. Trailing newlines normalized so determinism is
	// reproducible across operating systems.
	out := bytes.Buffer{}
	out.Write(bytes.TrimRight(header, "\n"))
	out.WriteString("\n")
	out.Write(bytes.TrimRight(body.Bytes(), "\n"))
	out.WriteString("\n")
	out.Write(bytes.TrimRight(footer, "\n"))
	out.WriteString("\n")

	if _, err := os.Stdout.Write(out.Bytes()); err != nil {
		fail("write stdout: %v", err)
	}
}

// genSubcommandSection runs `kensa <cmd> --help` and wraps the
// captured help text in a roff `.SS` subsection.
func genSubcommandSection(binPath, cmd string) (string, error) {
	abs, err := filepath.Abs(binPath)
	if err != nil {
		return "", err
	}
	out, err := exec.Command(abs, cmd, "--help").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("exec %s %s --help: %v\n%s", abs, cmd, err, out)
	}
	helpText := strings.TrimRight(string(out), "\n")

	var b strings.Builder
	fmt.Fprintf(&b, ".SS %s\n", strings.ToUpper(cmd))
	// Preformatted block so the help text's column alignment
	// (flag names + descriptions) renders verbatim. .nf =
	// no-fill (don't word-wrap), .fi = fill (resume normal).
	b.WriteString(".nf\n")
	for _, line := range strings.Split(helpText, "\n") {
		b.WriteString(escapeRoffLine(line))
		b.WriteString("\n")
	}
	b.WriteString(".fi\n")
	b.WriteString(".PP\n")
	return b.String(), nil
}

// escapeRoffLine escapes the roff special characters in a help-text
// line so the manpage renders without formatting corruption.
//
// Critical escapes:
//   - Leading "." or "'" at line-start would be interpreted as a
//     roff command. Prefix with `\&` (zero-width space) to suppress.
//   - Backslash `\` is roff's escape character; double it.
//   - Hyphen-minus `-` should be escaped as `\-` so it renders as a
//     visible minus sign rather than a soft hyphen (matters for
//     flag names like `--rules-dir`).
//
// The bare-prefix-dot guard runs LAST so we don't double-escape
// the backslash we just inserted.
func escapeRoffLine(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `-`, `\-`)
	if len(s) > 0 && (s[0] == '.' || s[0] == '\'') {
		s = `\&` + s
	}
	return s
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen-manpage: "+format+"\n", args...)
	os.Exit(1)
}
