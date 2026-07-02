package auditruleset

import "strings"

// managedHeader is the marker line Kensa writes at the top of a drop-in it
// creates. It is preserved on merge and ignored when deciding whether a file
// still holds any audit rule after a rollback.
const managedHeader = "# Managed by Kensa."

// mergeRuleLines merges ruleLines into the existing drop-in content, appending
// only the lines not already present (exact match after trimming) and
// preserving every existing line. It returns the new content and the lines it
// actually added.
//
// This is the fix for the shared-file clobber: audit rules deliberately group
// into shared drop-ins by CIS convention (e.g. 50-privileged.rules), and the
// pre-v0.7.2 whole-file overwrite let each rule's Apply truncate the others'
// lines. Merging preserves siblings. When the file is empty/absent the content
// starts with the managed header.
func mergeRuleLines(existing string, ruleLines []string) (merged string, added []string) {
	var lines []string
	present := map[string]bool{}
	if strings.TrimSpace(existing) != "" {
		lines = strings.Split(strings.TrimRight(existing, "\n"), "\n")
		for _, l := range lines {
			present[strings.TrimSpace(l)] = true
		}
	} else {
		lines = []string{managedHeader}
	}
	for _, l := range ruleLines {
		key := strings.TrimSpace(l)
		if key == "" || present[key] {
			continue
		}
		lines = append(lines, l)
		present[key] = true
		added = append(added, l)
	}
	return strings.Join(lines, "\n") + "\n", added
}

// removeRuleLines removes the given lines (exact match after trimming) from the
// drop-in content and reports whether any audit rule line remains — a non-blank
// line that is not a comment. Rollback uses remaining==false to decide the file
// can be deleted rather than left as an empty managed stub, and removes only
// the lines the rolling-back rule added, so a sibling rule's line in a shared
// drop-in survives.
func removeRuleLines(content string, remove []string) (reduced string, remaining bool) {
	if len(remove) == 0 {
		return content, hasRuleLine(content)
	}
	rm := map[string]bool{}
	for _, l := range remove {
		rm[strings.TrimSpace(l)] = true
	}
	var kept []string
	for _, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if rm[strings.TrimSpace(l)] {
			continue
		}
		kept = append(kept, l)
	}
	reduced = strings.Join(kept, "\n") + "\n"
	return reduced, hasRuleLine(reduced)
}

// hasRuleLine reports whether content holds at least one audit rule line
// (non-blank, non-comment).
func hasRuleLine(content string) bool {
	for _, l := range strings.Split(content, "\n") {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") {
			return true
		}
	}
	return false
}
