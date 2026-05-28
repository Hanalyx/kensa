// Command comment-lint fails when a Go // comment contains a planning label: a
// planning noun (Phase, Stage, Stream, Option, Milestone, Iteration, Increment,
// Workstream) followed by a bare identifier — a number or a single capital
// letter, the kind of label that lives in roadmaps and meeting notes. Such
// labels point into plans and discussions a future reader of the code cannot
// resolve; comments must explain intent in self-contained terms. See the
// "Comments" section of CONTRIBUTING.md for the rule and worked examples.
//
// A label immediately followed by a colon is exempt: that form names a step of
// an algorithm in the file (the engine labels its transaction steps that way),
// which is self-contained rather than a roadmap reference. A comment carrying
// the directive planlint:allow is also skipped, for the rare genuine case.
//
// By default it lints only the lines a change ADDS relative to a base ref, so
// the rule applies to new code without a big-bang rewrite of legacy comments.
//
//	comment-lint                 lint added lines vs origin/main
//	comment-lint -base main      ... vs a different base ref
//	comment-lint -all [paths]    lint every tracked .go file's // comments
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var (
	labelRe = regexp.MustCompile(`\b(Phase|Stage|Stream|Option|Milestone|Iteration|Increment|Workstream)[ \t-]+([0-9]+(\.[0-9]+)?|[A-Z])\b`)
	hunkRe  = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)`)
)

type finding struct {
	file  string
	line  int
	label string
}

// commentText returns the text after the first "//" in a line, or "" if the
// line has no line comment. Best-effort: a "//" inside a string literal is
// treated as a comment, and Go block comments are not inspected — both are rare
// and out of this gate's scope (line comments).
func commentText(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[i+2:]
	}
	return ""
}

// planningLabel returns the first planning label in a comment's text, or "".
// A label immediately followed by ':' is exempt (a self-contained step heading).
func planningLabel(comment string) string {
	if strings.Contains(comment, "planlint:allow") {
		return ""
	}
	for _, loc := range labelRe.FindAllStringIndex(comment, -1) {
		if loc[1] < len(comment) && comment[loc[1]] == ':' {
			continue
		}
		return strings.TrimSpace(comment[loc[0]:loc[1]])
	}
	return ""
}

// lintDiff inspects only the comment lines added relative to base.
func lintDiff(base string) ([]finding, error) {
	out, err := exec.Command("git", "diff", "--unified=0", "--no-color", base+"...", "--", "*.go").Output()
	if err != nil {
		return nil, fmt.Errorf("git diff against %q (is the base ref fetched?): %w", base, err)
	}
	var findings []finding
	var file string
	var newLine int
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "+++ b/"):
			file = strings.TrimPrefix(l, "+++ b/")
		case strings.HasPrefix(l, "@@"):
			if m := hunkRe.FindStringSubmatch(l); m != nil {
				newLine, _ = strconv.Atoi(m[1])
			}
		case strings.HasPrefix(l, "+"):
			if lbl := planningLabel(commentText(l[1:])); lbl != "" {
				findings = append(findings, finding{file, newLine, lbl})
			}
			newLine++
		case strings.HasPrefix(l, "-"):
			// a removed line does not advance the new-file counter
		}
	}
	return findings, sc.Err()
}

// lintAll inspects every // comment in all tracked .go files under paths
// (default: the whole repo).
func lintAll(paths []string) ([]finding, error) {
	args := []string{"ls-files"}
	if len(paths) > 0 {
		args = append(args, "--") // restrict to .go under the given paths
		args = append(args, paths...)
	} else {
		args = append(args, "*.go")
	}
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var findings []finding
	for _, file := range strings.Fields(string(out)) {
		if !strings.HasSuffix(file, ".go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for n, line := range strings.Split(string(data), "\n") {
			if lbl := planningLabel(commentText(line)); lbl != "" {
				findings = append(findings, finding{file, n + 1, lbl})
			}
		}
	}
	return findings, nil
}

func main() {
	all := flag.Bool("all", false, "lint all tracked .go comments, not just added lines")
	base := flag.String("base", "origin/main", "base ref for diff mode")
	flag.Parse()

	var (
		findings []finding
		err      error
	)
	if *all {
		findings, err = lintAll(flag.Args())
	} else {
		findings, err = lintDiff(*base)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "comment-lint:", err)
		os.Exit(2)
	}
	for _, f := range findings {
		fmt.Printf("%s:%d: planning label %q in a comment — state the intent instead (CONTRIBUTING.md, \"Comments\")\n", f.file, f.line, f.label)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "\ncomment-lint: %d planning label(s) found\n", len(findings))
		os.Exit(1)
	}
}
