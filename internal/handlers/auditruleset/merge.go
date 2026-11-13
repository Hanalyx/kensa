package auditruleset

import "strings"

// managedHeader is the marker line Kensa writes at the top of a drop-in it
// creates. It is preserved on merge, and a file Kensa created that holds
// only it after a rollback is removed.
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

// fileRestore is what rollback does to the drop-in.
type fileRestore struct {
	// remove deletes the file; otherwise content is written.
	remove  bool
	content string
}

// restoreFile decides the rollback of the drop-in from the file as it is
// now (current, and whether it exists), the capture (prior content, whether
// the file existed, and whether capture recorded them), and the lines Apply
// added.
//
// If the file is exactly what Apply wrote, nothing has touched it since, so
// the prior bytes come back as they were: the file is removed if Kensa
// created it, and otherwise rewritten byte for byte, even when it holds only
// comments, blank lines or nothing, and with its trailing newline state.
// Apply's merge normalizes that state, so a byte-for-byte restore needs the
// capture, not the current file.
//
// If the file changed after Apply only by lines appended to what Apply
// wrote, as a sibling rule's merge or an operator's echo appends them, the
// prior bytes come back followed by those lines (a newline is added between
// them when the prior file did not end in one). Any other change keeps every
// byte but the lines Apply added. Either way the file is removed only if
// Kensa created it and nothing but its own header and blank lines remain. A
// file that is gone now stays gone.
func restoreFile(current string, currentExists bool, prior string, existed, captured bool, added []string) fileRestore {
	if !currentExists {
		return fileRestore{remove: true}
	}
	if captured {
		applied, _ := mergeRuleLines(prior, added)
		if current == applied {
			if !existed {
				return fileRestore{remove: true}
			}
			return fileRestore{content: prior}
		}
		if existed && strings.HasPrefix(current, applied) {
			p := prior
			if p != "" && !strings.HasSuffix(p, "\n") {
				p += "\n"
			}
			return fileRestore{content: p + dropLines(current[len(applied):], added)}
		}
	}
	reduced := dropLines(current, added)
	if (!captured || !existed) && onlyManagedHeader(reduced) {
		return fileRestore{remove: true}
	}
	return fileRestore{content: reduced}
}

// dropLines removes the lines in drop (exact match after trimming) from
// content and keeps every other byte, including each kept line's ending and
// whether the content ends in a newline.
func dropLines(content string, drop []string) string {
	rm := map[string]bool{}
	for _, l := range drop {
		if t := strings.TrimSpace(l); t != "" {
			rm[t] = true
		}
	}
	if len(rm) == 0 {
		return content
	}
	var b strings.Builder
	for _, seg := range strings.SplitAfter(content, "\n") {
		if rm[strings.TrimSpace(seg)] {
			continue
		}
		b.WriteString(seg)
	}
	return b.String()
}

// onlyManagedHeader reports whether content holds nothing but Kensa's
// header and blank lines.
func onlyManagedHeader(content string) bool {
	for _, l := range strings.Split(content, "\n") {
		if t := strings.TrimSpace(l); t != "" && t != managedHeader {
			return false
		}
	}
	return true
}
