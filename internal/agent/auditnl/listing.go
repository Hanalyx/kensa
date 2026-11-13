package auditnl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/elastic/go-libaudit/v2/rule"
)

// Kernel constants from linux/audit.h.
const (
	auditFilterExit    = 4    // AUDIT_FILTER_EXIT
	auditFilterPrepend = 0x10 // AUDIT_FILTER_PREPEND: the rule was added with -A
	auditNever         = 0    // AUDIT_NEVER
	auditAlways        = 2    // AUDIT_ALWAYS
	auditWatchField    = 105  // AUDIT_WATCH: path=, an inode watch
	auditDirField      = 107  // AUDIT_DIR: dir=, a subtree watch
	auditMaxFields     = 64
	auditHeaderSize    = 12 + 4*4*auditMaxFields + 4 // through buflen
)

// RuleText renders one rule from GetRules as an auditctl-syntax line.
//
// It is rule.ToCommandLine with two changes. First, the kernel reports a
// rule added with -A with AUDIT_FILTER_PREPEND set in its list word, which
// ToCommandLine rejects as an unknown list; RuleText clears that bit, since
// it records only where the rule was inserted, and auditctl -l prints such a
// rule as -a. Second, a watch. auditctl -l and ToCommandLine both print a
// path= rule and a dir= rule as "-w <path>", so the listing cannot show
// whether a directory has an inode watch or a subtree watch. The wire format
// can: the field is AUDIT_WATCH or AUDIT_DIR. RuleText writes such a rule as
// "-a always,exit -S all -F path=<p> -F perm=<p>" or with dir=, so the type
// survives, and with its own action: a never rule of that shape, which both
// print as an always watch, keeps "never". Other rules come back as
// ToCommandLine prints them, with "-k" for the key and the machine arch
// rather than b64. Several keys stay joined by the kernel's \x01 separator,
// which the rule parser in internal/check splits.
func RuleText(wire []byte) (string, error) {
	if len(wire) < auditHeaderSize {
		return "", errors.New("auditnl: rule wire format too short")
	}
	ne := binary.NativeEndian
	w := append([]byte(nil), wire...)
	ne.PutUint32(w, ne.Uint32(w)&^auditFilterPrepend)
	text, err := rule.ToCommandLine(rule.WireFormat(w), false)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(text, "-w ") {
		return text, nil
	}
	typ, action, err := watchFieldType(w)
	if err != nil {
		return "", err
	}
	f := strings.Fields(text)
	var path, perm string
	var keys []string
	for i := 0; i+1 < len(f); i += 2 {
		switch f[i] {
		case "-w":
			path = f[i+1]
		case "-p":
			perm = f[i+1]
		case "-k":
			keys = append(keys, f[i+1])
		default:
			return "", fmt.Errorf("auditnl: unexpected token %q in watch %q", f[i], text)
		}
	}
	name := "path"
	if typ == auditDirField {
		name = "dir"
	}
	out := fmt.Sprintf("-a %s,exit -S all -F %s=%s -F perm=%s", action, name, path, perm)
	for _, k := range keys {
		out += " -F key=" + k
	}
	return out, nil
}

// watchFieldType reads the wire header of a rule ToCommandLine printed as a
// watch and returns its path field type and action. The layout is struct
// audit_rule_data: flags, action and field_count as u32, then mask[64],
// fields[64], values[64] and fieldflags[64], in host byte order. Only an
// exit-list rule with exactly one path or dir field is a watch here. The
// caller has cleared the prepend bit.
func watchFieldType(wire []byte) (uint32, string, error) {
	const fieldsAt = 12 + 4*auditMaxFields
	ne := binary.NativeEndian
	flags, action, count := ne.Uint32(wire[0:]), ne.Uint32(wire[4:]), ne.Uint32(wire[8:])
	act := map[uint32]string{auditAlways: "always", auditNever: "never"}[action]
	if flags != auditFilterExit || act == "" {
		return 0, "", fmt.Errorf("auditnl: watch-shaped rule on list %d action %d", flags, action)
	}
	if count > auditMaxFields {
		return 0, "", fmt.Errorf("auditnl: rule has %d fields", count)
	}
	var found uint32
	for i := uint32(0); i < count; i++ {
		switch t := ne.Uint32(wire[fieldsAt+4*i:]); t {
		case auditWatchField, auditDirField:
			if found != 0 {
				return 0, "", errors.New("auditnl: rule has more than one path or dir field")
			}
			found = t
		}
	}
	if found == 0 {
		return 0, "", errors.New("auditnl: watch-shaped rule has no path or dir field")
	}
	return found, act, nil
}

// ruleList returns the filter list a wire rule is on, without the prepend
// bit, or an error when the header is too short to say.
func ruleList(wire []byte) (uint32, error) {
	if len(wire) < auditHeaderSize {
		return 0, errors.New("auditnl: rule wire format too short")
	}
	return binary.NativeEndian.Uint32(wire) &^ auditFilterPrepend, nil
}

// auditListNames names the filter lists as auditctl's -a option does.
var auditListNames = map[uint32]string{
	0: "user", 1: "task", 2: "entry", 4: "exit", 5: "exclude", 6: "filesystem", 7: "io_uring",
}

// RulesText lists the loaded rules through netlink, rendered by RuleText.
//
// An exit-list rule that cannot be rendered is an error, never skipped, so a
// caller never reads a partial listing of the exit list as complete. A rule
// on another list (user, exclude, filesystem, io_uring) that cannot be
// rendered is left out, and its list name is returned in skipped (as
// auditctl names it, or "list N"): a caller asking about a rule on one of
// those lists must treat the listing as incomplete.
func RulesText(c AuditClient) (texts []string, skipped []string, err error) {
	wires, err := c.GetRules()
	if err != nil {
		return nil, nil, fmt.Errorf("auditnl: list rules: %w", err)
	}
	texts = make([]string, 0, len(wires))
	for _, w := range wires {
		t, rerr := RuleText(w)
		if rerr == nil {
			texts = append(texts, t)
			continue
		}
		list, lerr := ruleList(w)
		if lerr != nil || list == auditFilterExit {
			return nil, nil, fmt.Errorf("auditnl: render loaded rule: %w", rerr)
		}
		name, ok := auditListNames[list]
		if !ok {
			name = fmt.Sprintf("list %d", list)
		}
		skipped = append(skipped, name)
	}
	return texts, skipped, nil
}
