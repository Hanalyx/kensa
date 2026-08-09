package kernelio

import (
	"errors"
	"strings"
)

// ErrNoFstabEntry is returned when no non-comment /etc/fstab line has a
// mount-point field matching the requested mount point.
var ErrNoFstabEntry = errors.New("kernelio: no matching fstab entry")

// fstab format: whitespace-separated fields
//   1 device  2 mountpoint  3 fstype  4 options  5 dump  6 pass
// Comment lines start with '#'; blank lines are ignored.

// isFstabComment reports whether a line is blank or a comment.
func isFstabComment(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || strings.HasPrefix(t, "#")
}

// FstabFindLine returns the first non-comment line whose mount-point
// field (field 2) equals mountPoint, verbatim. found is false if none
// match. Used by Capture to record the prior line.
func FstabFindLine(content, mountPoint string) (line string, found bool) {
	for _, l := range strings.Split(content, "\n") {
		if isFstabComment(l) {
			continue
		}
		f := strings.Fields(l)
		if len(f) >= 2 && f[1] == mountPoint {
			return l, true
		}
	}
	return "", false
}

// FstabAddOptions returns content with each requested option appended to
// the options field (field 4) of every matching mount-point line that
// does not already carry it. The modified line's fields are re-joined
// with single spaces — matching the awk shell path so the two paths
// produce byte-identical fstab content. A matching line with fewer than
// four fields is malformed and left untouched. Returns ErrNoFstabEntry if
// no line matches.
func FstabAddOptions(content, mountPoint string, opts []string) (string, error) {
	lines := strings.Split(content, "\n")
	found := false
	for i, l := range lines {
		if isFstabComment(l) {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 2 || f[1] != mountPoint {
			continue
		}
		found = true
		if len(f) < 4 {
			continue // malformed entry; cannot edit the options field
		}
		existing := strings.Split(f[3], ",")
		have := make(map[string]bool, len(existing))
		for _, o := range existing {
			have[o] = true
		}
		for _, o := range opts {
			if o != "" && !have[o] {
				existing = append(existing, o)
				have[o] = true
			}
		}
		f[3] = strings.Join(existing, ",")
		lines[i] = strings.Join(f, " ")
	}
	if !found {
		return "", ErrNoFstabEntry
	}
	return strings.Join(lines, "\n"), nil
}

// FstabReplaceLine returns content with every matching mount-point line
// replaced verbatim by newLine. Used by Rollback to restore the captured
// prior line. Returns ErrNoFstabEntry if no line matches.
func FstabReplaceLine(content, mountPoint, newLine string) (string, error) {
	lines := strings.Split(content, "\n")
	found := false
	for i, l := range lines {
		if isFstabComment(l) {
			continue
		}
		f := strings.Fields(l)
		if len(f) >= 2 && f[1] == mountPoint {
			lines[i] = newLine
			found = true
		}
	}
	if !found {
		return "", ErrNoFstabEntry
	}
	return strings.Join(lines, "\n"), nil
}

// FstabRemoveLine returns content with every matching mount-point line
// removed. Used by Rollback to undo an entry this engine created: a mount
// point that had no fstab line before is only restored by taking the line
// away again, and FstabReplaceLine cannot express that.
//
// Returns ErrNoFstabEntry if no line matches, so a caller can tell "nothing to
// remove" from "removed it".
func FstabRemoveLine(content, mountPoint string) (string, error) {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	found := false
	for _, l := range lines {
		if !isFstabComment(l) {
			f := strings.Fields(l)
			if len(f) >= 2 && f[1] == mountPoint {
				found = true
				continue
			}
		}
		out = append(out, l)
	}
	if !found {
		return "", ErrNoFstabEntry
	}
	return strings.Join(out, "\n"), nil
}

// FstabRemoveOptions returns content with each requested option removed from
// the options field of every matching mount-point line. Options the line does
// not carry are ignored, so this is idempotent.
//
// An options field emptied of everything becomes "defaults" rather than an
// empty field, because an fstab line with a blank fourth field is malformed.
//
// Returns ErrNoFstabEntry if no line matches. A matching line with fewer than
// four fields is malformed and left untouched, matching FstabAddOptions.
func FstabRemoveOptions(content, mountPoint string, opts []string) (string, error) {
	drop := make(map[string]bool, len(opts))
	for _, o := range opts {
		if o != "" {
			drop[o] = true
		}
	}
	lines := strings.Split(content, "\n")
	found := false
	for i, l := range lines {
		if isFstabComment(l) {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 2 || f[1] != mountPoint {
			continue
		}
		found = true
		if len(f) < 4 {
			continue // malformed entry; cannot edit the options field
		}
		kept := make([]string, 0, len(f[3]))
		for _, o := range strings.Split(f[3], ",") {
			if !drop[o] {
				kept = append(kept, o)
			}
		}
		if len(kept) == 0 {
			kept = []string{"defaults"}
		}
		f[3] = strings.Join(kept, ",")
		lines[i] = strings.Join(f, " ")
	}
	if !found {
		return "", ErrNoFstabEntry
	}
	return strings.Join(lines, "\n"), nil
}

// FstabOptions returns the options field of the matching mount-point line,
// split on commas. found is false when no line matches or the line is
// malformed. Rollback uses it to decide whether an entry still carries options
// a sibling rule added, which is what makes removing the line safe or not.
func FstabOptions(content, mountPoint string) (opts []string, found bool) {
	line, ok := FstabFindLine(content, mountPoint)
	if !ok {
		return nil, false
	}
	f := strings.Fields(line)
	if len(f) < 4 {
		return nil, false
	}
	return strings.Split(f[3], ","), true
}
