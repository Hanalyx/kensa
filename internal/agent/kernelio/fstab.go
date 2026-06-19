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
