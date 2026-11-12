package check

import "strings"

// AuditLineMaybeLoaded reports whether a staged audit rule line may still be
// loaded: AuditLineLoaded finds it, or the field-subset matcher Kensa used
// before AuditLineLoaded compared the whole kernel rule finds it.
//
// It exists for one caller, the audit_rule_set shell staged-rollback
// verdict, and it is an interim. On that path a false "not loaded" makes the
// rollback report a clean restore while the host still carries the rule. The
// canonical form in AuditLineLoaded has not yet been checked against every
// form auditctl -l prints, so the older, more lenient matcher is kept as a
// second opinion. The union can only add "loaded" answers, never remove
// one. Its cost is that a loaded never line with the same fields still reads
// as the staged rule, a cautious PartialRestore. Remove it once the canonical
// form is verified against real auditctl -l output.
func AuditLineMaybeLoaded(rule string, loaded []string) bool {
	return AuditLineLoaded(rule, loaded) || legacyAuditLineLoaded(rule, loaded)
}

// legacyAuditLineLoaded is the earlier matcher: it compares only the fields
// the rule line carries (arch, path, perm, exit, key, syscall set and auid
// filters), so it never misses a loaded rule that AuditLineLoaded would find
// by those fields. Kept only for AuditLineMaybeLoaded.
func legacyAuditLineLoaded(rule string, loaded []string) bool {
	// Watch rules ("-w <path> -p <perms> -k <key>") print verbatim: full match.
	if strings.HasPrefix(rule, "-w") {
		norm := normaliseAuditRule(rule)
		for _, l := range loaded {
			if normaliseAuditRule(l) == norm {
				return true
			}
		}
		return false
	}

	// Syscall / exec rules: match on the distinguishing fields the rule carries.
	archTok, hasArch := legacyAuditFToken(rule, "arch")
	pathTok, hasPath := legacyAuditFToken(rule, "path")
	permTok, hasPerm := legacyAuditFToken(rule, "perm")
	exitTok, hasExit := legacyAuditFToken(rule, "exit")
	key := legacyExtractAuditKey(rule)
	want := legacyAuditSyscallSet(rule)
	hasDistinguisher := hasArch || hasPath || hasExit || len(want) > 0

	for _, l := range loaded {
		if hasArch && !legacyAuditFieldEqual(l, "arch", archTok) {
			continue
		}
		if hasPath && !legacyAuditFieldEqual(l, "path", pathTok) {
			continue
		}
		if hasPerm && !legacyAuditFieldEqual(l, "perm", permTok) {
			continue
		}
		if hasExit && !legacyAuditFieldEqual(l, "exit", exitTok) {
			continue
		}
		if key != "" && legacyExtractAuditKey(l) != key {
			continue
		}
		if len(want) > 0 && !legacySameStringSet(want, legacyAuditSyscallSet(l)) {
			continue
		}
		if !legacyAuidTokensPresent(rule, l) {
			continue
		}
		// With no distinguishing field at all, fall back to a full-line compare
		// so a bare keyed rule can't be satisfied by an unrelated line.
		if !hasDistinguisher && normaliseAuditRule(l) != normaliseAuditRule(rule) {
			continue
		}
		return true
	}
	return false
}

// legacyAuidTokensPresent reports whether every auid filter in the rule appears in
// the loaded line. The auid filters (auid>=1000, auid=0, auid!=unset)
// distinguish otherwise-identical syscall lines — e.g. the setxattr control's
// auid>=1000 and auid=0 variants. auditctl -l prints auid!=unset as auid!=-1,
// so normalise before comparing.
func legacyAuidTokensPresent(rule string, loadedLine string) bool {
	fields := strings.Fields(rule)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "-F" || !strings.HasPrefix(fields[i+1], "auid") {
			continue
		}
		tok := fields[i+1]
		if tok == "auid!=unset" {
			tok = "auid!=-1"
		}
		if !legacyAuditFieldPresent(loadedLine, tok) {
			return false
		}
	}
	return true
}

// legacyAuditSyscallSet returns the set of syscalls named in a rule's "-S a,b,c"
// tokens (auditctl -l re-sorts the list, so compare as a set, not a string).
func legacyAuditSyscallSet(rule string) map[string]bool {
	set := map[string]bool{}
	fields := strings.Fields(rule)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-S" {
			for _, sc := range strings.Split(fields[i+1], ",") {
				if sc != "" {
					set[sc] = true
				}
			}
		}
	}
	return set
}

// legacySameStringSet reports whether two string sets are equal.
func legacySameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// legacyExtractAuditKey returns the value following -k in an audit rule string,
// or empty string if none is present.
func legacyExtractAuditKey(rule string) string {
	fields := strings.Fields(rule)
	for i, f := range fields {
		if f == "-k" && i+1 < len(fields) {
			return fields[i+1]
		}
		if strings.HasPrefix(f, "-k") && len(f) > 2 {
			return f[2:]
		}
		// auditctl -l normalises "-k key" to "-F key=key"; accept that form too
		// so the key can be compared exactly against a loaded line.
		if strings.HasPrefix(f, "key=") {
			return f[len("key="):]
		}
	}
	return ""
}

// legacyAuditFieldEqual reports whether line carries the exact "-F <field>=<value>"
// token wantTok — a WHOLE-VALUE match, NOT a substring. This is what stops
// "-F path=/usr/bin/su" from matching a loaded "-F path=/usr/bin/sudo" (su is a
// prefix of sudo); the substring form silently conflated distinct rules.
func legacyAuditFieldEqual(line, field, wantTok string) bool {
	got, ok := legacyAuditFToken(line, field)
	return ok && got == wantTok
}

// legacyAuditFieldPresent reports whether tok is a complete whitespace-delimited
// field of line (not a substring — so "auid>=1000" does not match a loaded
// "auid>=10000").
func legacyAuditFieldPresent(line, tok string) bool {
	for _, f := range strings.Fields(line) {
		if f == tok {
			return true
		}
	}
	return false
}

// legacyAuditFToken returns the "-F <field>=<value>" token for the named field in an
// audit rule (e.g. legacyAuditFToken(rule, "path") -> `-F path=/usr/bin/sudo`, true),
// or ("", false) if the field is absent. The token is matched verbatim against
// auditctl -l output, which preserves "-F path=" / "-F perm=".
func legacyAuditFToken(rule, field string) (string, bool) {
	fields := strings.Fields(rule)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-F" && strings.HasPrefix(fields[i+1], field+"=") {
			return "-F " + fields[i+1], true
		}
	}
	return "", false
}
