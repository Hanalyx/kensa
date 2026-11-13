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
// prior bytes come back followed by those lines, kept as they are (a newline
// is added between them when the prior file did not end in one). Any other
// change keeps every byte but what Apply added: one copy of each of its
// lines, and the managed header when the prior file held only whitespace
// (the only case in which Apply adds one). The file is removed when nothing
// but the header and blank lines remain and Kensa created it before this
// change. It is also removed when Kensa's header is still in it, nothing else
// is, and the prior content starts with the header (a sibling rule's
// transaction created it) or the capture is missing. An operator file that
// holds only that header line is therefore removed in that case too. A file
// that is gone now stays gone. Only content is restored; the file's mode,
// owner and security label are not captured.
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
			// The appended lines came after Apply, so none of them is ours.
			return fileRestore{content: p + current[len(applied):]}
		}
	}
	drop := append([]string(nil), added...)
	if captured && existed && strings.TrimSpace(prior) == "" {
		// Apply's merge puts the header only into a file that held nothing
		// but whitespace, so only then is a header line Apply's to drop.
		drop = append(drop, managedHeader)
	}
	reduced := dropLines(current, drop)
	switch {
	case !onlyManagedHeader(reduced):
		return fileRestore{content: reduced}
	case captured && !existed:
		// Kensa created the file and nothing of anyone else's is left.
		return fileRestore{remove: true}
	case (!captured || strings.HasPrefix(strings.TrimLeft(prior, " \t\r\n"), managedHeader)) && hasManagedHeader(reduced):
		// The file is Kensa's own stub: a sibling transaction created it, or
		// the capture is missing, and the header is still all it holds.
		return fileRestore{remove: true}
	}
	return fileRestore{content: reduced}
}

// hasManagedHeader reports whether content holds Kensa's header line.
func hasManagedHeader(content string) bool {
	for _, l := range strings.Split(content, "\n") {
		if strings.TrimSpace(l) == managedHeader {
			return true
		}
	}
	return false
}

// dropLines removes one copy of each line in drop (exact match after
// trimming, first occurrence) from content and keeps every other byte,
// including each kept line's ending and whether the content ends in a
// newline. A second copy, such as one an operator added after Apply, stays.
func dropLines(content string, drop []string) string {
	rm := map[string]int{}
	for _, l := range drop {
		if t := strings.TrimSpace(l); t != "" {
			rm[t]++
		}
	}
	if len(rm) == 0 {
		return content
	}
	var b strings.Builder
	for _, seg := range strings.SplitAfter(content, "\n") {
		if t := strings.TrimSpace(seg); rm[t] > 0 {
			rm[t]--
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
