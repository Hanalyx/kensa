package check

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/varsub"
)

// ErrNotAssessable means the check ran far enough to establish that it cannot
// reach a verdict on this host, and that no verdict is the honest answer.
//
// The scan maps it to skipped rather than error. Error says something went
// wrong; nothing has. What it reports is that the operator has not yet supplied
// something only they can supply, which is a state a compliance run should show
// plainly and not dress up as a result.
//
// It exists because a check method had no way to say this. Result carries only
// Passed, so every path out of a check was pass, fail, or something broke.
var ErrNotAssessable = errors.New("check: not assessable on this host")

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
		// Not a pass and not a fail. An empty declared set read one way makes
		// every member unauthorized, and read the other makes every member
		// acceptable; neither is true. What is true is that nobody has said
		// what is allowed, so there is no verdict to give.
		//
		// This is a SKIP rather than an error, because nothing is broken. An
		// empty set is how an operator who has not yet written their policy
		// looks, and that is a normal state on a fleet that has just installed
		// Kensa, not a malfunction. The reason travels with it so the run says
		// what to declare.
		return false, "", fmt.Errorf(
			"%w: no authorized members are declared, so there is nothing to compare against. "+
				"Declare them as a list variable, for example in <config-dir>/defaults.yml, "+
				"or pass --var NAME=a,b", ErrNotAssessable)
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
	// An observed line may carry more than one name for the SAME thing, joined
	// by alias_separator. A local account is the case: a site may authorize it
	// by user name or by numeric UID, and both refer to one account. Splitting
	// those into two members would report the UID as an unauthorized extra on a
	// host where only the name was declared, which is a finding about nothing.
	aliasSep := optionalStringParam(params, "alias_separator", "")
	entities := parseEntities(res.Stdout, aliasSep)

	authSet := make(map[string]struct{}, len(authorized))
	for _, a := range authorized {
		authSet[a] = struct{}{}
	}
	var unauthorized []string
	matched := make(map[string]struct{})
	for _, e := range entities {
		ok := false
		for _, id := range e.ids {
			if _, found := authSet[id]; found {
				ok = true
				matched[id] = struct{}{}
			}
		}
		if !ok {
			unauthorized = append(unauthorized, e.primary)
		}
	}
	var missing []string
	for _, a := range authorized {
		if _, ok := matched[a]; !ok {
			missing = append(missing, a)
		}
	}
	observed := make([]string, 0, len(entities))
	for _, e := range entities {
		observed = append(observed, e.primary)
	}

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

// entity is one thing on the host, which may answer to several names. The first
// is what gets reported, because it is the one an operator recognizes.
type entity struct {
	primary string
	ids     []string
}

// parseEntities turns the observing command's output into one entity per
// non-empty line. With no separator each line is a single name, which is the
// original behavior and what most checks want.
func parseEntities(raw, sep string) []entity {
	var out []entity
	seen := make(map[string]struct{})
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		if sep == "" {
			out = append(out, entity{primary: line, ids: []string{line}})
			continue
		}
		var ids []string
		for _, part := range strings.Split(line, sep) {
			if part = strings.TrimSpace(part); part != "" {
				ids = append(ids, part)
			}
		}
		if len(ids) == 0 {
			continue
		}
		out = append(out, entity{primary: ids[0], ids: ids})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].primary < out[j].primary })
	return out
}
