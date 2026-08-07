package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/varsub"
)

// checkSetCompare answers "only authorized X are present" by comparing a set
// observed on the host against a set the operator declared.
//
// Both halves are needed because neither alone is a compliance answer. NIST
// separates the organizational determination ("the authorized users are
// identified") from the technical enforcement ("access is limited to authorized
// users"). Kensa cannot know who a site authorized, so the operator declares
// it; the host supplies what is actually there; this compares them. Without a
// declared set the question has no answer, which is why an empty one is an
// error rather than a pass.
//
// The comparison runs HERE, in Go, not in generated shell. Only the observing
// command runs on the host. Its output and the declared list are split on this
// side, so neither set is ever re-interpreted by a shell, and a member cannot
// be word-split into two members it was never meant to be.
func checkSetCompare(ctx context.Context, transport api.Transport, params api.Params) (bool, string, error) {
	observedCmd := optionalStringParam(params, "observed_command", "")
	if observedCmd == "" {
		return false, "", fmt.Errorf("check: missing required param \"observed_command\"")
	}
	rawAuthorized, present := stringParamPresent(params, "authorized")
	if !present {
		return false, "", fmt.Errorf("check: missing required param \"authorized\"")
	}

	authorized := splitSet(rawAuthorized, varsub.ListSeparator)
	if len(authorized) == 0 {
		// Deliberately an error, not a pass and not a skip. An empty declared
		// set would make every member unauthorized (a false fail) or every
		// member acceptable (a false pass) depending on which way it is read.
		// Neither is true; the truth is that nobody has said what is allowed.
		return false, "", fmt.Errorf(
			"check: \"authorized\" is empty, so there is nothing to compare against. " +
				"Declare the permitted members as a list variable, for example in " +
				"<config-dir>/defaults.yml, or pass --var NAME=a,b")
	}

	res, err := transport.Run(ctx, observedCmd)
	if err != nil {
		return false, "", fmt.Errorf("check set_compare: transport error: %w", err)
	}
	if res.ExitCode != 0 {
		return false, "", fmt.Errorf(
			"check set_compare: the observing command exited %d, so what is on the host is unknown: %s",
			res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	observed := splitSet(res.Stdout, "\n")

	unauthorized := difference(observed, authorized)
	missing := difference(authorized, observed)

	// Only the unauthorized half decides the verdict. A declared member that is
	// absent is reported because an operator wants to know their list has drifted,
	// but an account that does not exist cannot grant access, so it is not a
	// finding on its own.
	detail := fmt.Sprintf("observed %d, authorized %d", len(observed), len(authorized))
	if len(missing) > 0 {
		detail += fmt.Sprintf("; declared but absent: %s", strings.Join(missing, ", "))
	}
	if len(unauthorized) > 0 {
		return false, fmt.Sprintf("present but not authorized: %s (%s)",
			strings.Join(unauthorized, ", "), detail), nil
	}
	return true, fmt.Sprintf("every observed member is authorized (%s)", detail), nil
}

// splitSet turns raw text into a sorted, de-duplicated set of non-empty members.
func splitSet(raw, sep string) []string {
	seen := make(map[string]struct{})
	for _, f := range strings.Split(raw, sep) {
		f = strings.TrimSpace(f)
		if f != "" {
			seen[f] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	// Sorted so Detail and Evidence read the same on every run; an operator
	// diffing two scans should see real change, not map iteration order.
	sort.Strings(out)
	return out
}

// difference returns the members of a that are not in b.
func difference(a, b []string) []string {
	inB := make(map[string]struct{}, len(b))
	for _, s := range b {
		inB[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := inB[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}
