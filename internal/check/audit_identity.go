package check

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// Two questions about audit rules look alike and must not share an answer.
//
//   - Kernel duplicate identity (AuditRuleIdentity): will auditctl, loading
//     both rules.d lines at boot on this host, build one kernel rule twice?
//     The kernel then answers "Rule exists" and the load aborts. The
//     audit_rule_set guard asks this before it writes a drop-in.
//   - Compliance coverage (auditRuleCovers): does a rule auditctl -l lists
//     record every event a requirement asks for? audit_rule_exists asks this.
//
// Identity is exact. Coverage allows a loaded rule over more syscalls. A rule
// that covers another is often not its duplicate: the kernel loads both.

// auditWatchKindUnknown is the reason given when a watch's field type, path
// (an inode watch) or dir (a subtree watch), cannot be established.
const auditWatchKindUnknown = "whether the watch is a path or a dir field is not known"

// AuditIdentity is the answer to the duplicate question.
type AuditIdentity int

const (
	// AuditDistinct: some part of the two kernel rules provably differs, so
	// the kernel loads both. Only a measured or resolved difference gives it.
	AuditDistinct AuditIdentity = iota
	// AuditSame: every part resolved and matched; one kernel rule.
	AuditSame
	// AuditUnresolved: no part provably differs, and some part could not be
	// resolved. A guard treats it as Same.
	AuditUnresolved
)

func (i AuditIdentity) String() string {
	switch i {
	case AuditDistinct:
		return "distinct"
	case AuditSame:
		return "same"
	default:
		return "unresolved"
	}
}

// AuditPathKind is what a watched path is on the target, as stat sees it.
type AuditPathKind string

const (
	AuditPathDir     AuditPathKind = "dir"
	AuditPathOther   AuditPathKind = "other" // exists, not a directory
	AuditPathSymlink AuditPathKind = "symlink"
	AuditPathMissing AuditPathKind = "missing"
)

// AuditTarget holds the facts about the host that decide what kernel rule
// auditctl builds from a line. A fact that is absent is unresolved.
type AuditTarget struct {
	Machine         string // uname -m
	AuditctlVersion string // from auditctl -v
	// UIDs and GIDs hold names resolved through the files service only.
	// auditctl resolves names at boot, when a directory service may not be
	// up, so a name known only through sssd or LDAP is left unresolved.
	UIDs  map[string]int64
	GIDs  map[string]int64
	Paths map[string]AuditPathKind
	// Syscalls holds syscall numbers from ausyscall on the host, keyed by
	// the arch token as a rule writes it ("b64", "b32", "x86_64", ..., or
	// "" for a rule with no arch, which auditctl reads as the machine's
	// own) and then by name. A name ausyscall does not resolve is absent.
	Syscalls map[string]map[string]int64
}

// auditSyscallNameRe is what a syscall name in a rule may look like before
// the probe asks ausyscall about it.
var auditSyscallNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// auditArchTokenRe is an arch token the probe will look syscalls up for.
var auditArchTokenRe = regexp.MustCompile(`^(b64|b32|x86_64|i386|aarch64|arm)$`)

// auditMeasuredAuditctl lists the audit userspace versions whose auditctl -l
// output was captured on x86_64 (RHEL 10.2 and Rocky 9.8). The perm-class
// table, the arch aliases and the errno names are trusted only for these.
var auditMeasuredAuditctl = map[string]bool{"3.1.5": true, "4.0.3": true}

// measured reports whether the target is a machine arch and audit version
// whose auditctl behavior was captured.
func (t *AuditTarget) measured() bool {
	return t != nil && t.Machine == "x86_64" && auditMeasuredAuditctl[t.AuditctlVersion]
}

// auditPermClassFor returns the captured syscall list auditctl loads for a
// path= or dir= rule with this arch and perm and no -S, or false outside the
// measured machine arch and versions.
func auditPermClassFor(t *AuditTarget, arch, perm string) ([]string, bool) {
	if !t.measured() {
		return nil, false
	}
	lists := auditPermClass[arch][perm]
	if len(lists) != 1 {
		return nil, false
	}
	return lists[0], true
}

var (
	auditNameRe    = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*\$?$`)
	auditDecimalRe = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	auditVersionRe = regexp.MustCompile(`([0-9]+\.[0-9]+(\.[0-9]+)?)`)
)

var auditUIDFields = map[string]bool{
	"uid": true, "euid": true, "suid": true, "fsuid": true, "auid": true, "loginuid": true, "obj_uid": true,
}

var auditGIDFields = map[string]bool{
	"gid": true, "egid": true, "sgid": true, "fsgid": true, "obj_gid": true,
}

// auditPassThrough names the -F fields auditctl -l shows auditctl passing
// through as one field of their own, so a field present on one side only
// gives the kernel rules different field counts. Each is in the captures
// (testdata/auditctl): auid (auid!=unset lists as auid!=-1), euid (pair 14
// lists -F euid=0), exit (pair 11 lists -F exit=-EACCES). A one-sided field
// not named here, such as arch or perm, or the path and dir fields a -w
// makes, is unresolved: auditctl may add, drop or rewrite it.
var auditPassThrough = map[string]bool{"auid": true, "euid": true, "exit": true}

// auditErrno maps errno names to the asm-generic numbers. Errno numbers are
// a fact of the machine arch, not the audit version. Numbers 1 to 34 (the
// asm-generic errno-base set) are the same on every Linux arch; the rest are
// used only on x86_64 and aarch64, which share them. The name and number
// pair is captured on x86_64.
var auditErrno = map[string]int64{
	"EPERM": 1, "ENOENT": 2, "ESRCH": 3, "EINTR": 4, "EIO": 5, "ENXIO": 6, "E2BIG": 7, "ENOEXEC": 8,
	"EBADF": 9, "ECHILD": 10, "EAGAIN": 11, "ENOMEM": 12, "EACCES": 13, "EFAULT": 14, "ENOTBLK": 15,
	"EBUSY": 16, "EEXIST": 17, "EXDEV": 18, "ENODEV": 19, "ENOTDIR": 20, "EISDIR": 21, "EINVAL": 22,
	"ENFILE": 23, "EMFILE": 24, "ENOTTY": 25, "ETXTBSY": 26, "EFBIG": 27, "ENOSPC": 28, "ESPIPE": 29,
	"EROFS": 30, "EMLINK": 31, "EPIPE": 32, "EDOM": 33, "ERANGE": 34, "EDEADLK": 35, "ENAMETOOLONG": 36,
	"ENOLCK": 37, "ENOSYS": 38, "ENOTEMPTY": 39, "ELOOP": 40, "EOPNOTSUPP": 95, "ETIMEDOUT": 110,
	// Aliases: two names, one number. Comparison is by number, so these
	// resolve as one value.
	"EWOULDBLOCK": 11, "EDEADLOCK": 35, "ENOTSUP": 95,
}

// auditArchByMachine maps arch spellings to the kernel arch, per machine.
// What b64 and b32 mean is a fact about the machine, not the audit version:
// on x86_64 the b64 and x86_64 pair and the b32 and i386 pair are captured
// as one rule ("Rule exists"); aarch64 follows libaudit's table. A literal
// arch name means that arch on any machine. Equating spellings can only add
// a refusal.
var auditArchByMachine = map[string]map[string]string{
	"x86_64":  {"b64": "x86_64", "b32": "i386"},
	"aarch64": {"b64": "aarch64", "b32": "arm"},
}

// auditArchNames are the literal arch names the predicate knows.
var auditArchNames = map[string]bool{"x86_64": true, "i386": true, "aarch64": true, "arm": true}

// AuditTargetProbe returns one read-only shell command that reports, for
// the given rule lines, the facts AuditTarget holds: the machine arch, the
// auditctl version, each uid and gid name through the files service, and
// the type of each watched path.
func AuditTargetProbe(lines []string) string {
	return auditTargetProbe(lines, true)
}

// auditTargetProbe builds the probe; withSyscalls adds the ausyscall
// lookups, which only the duplicate guard uses.
func auditTargetProbe(lines []string, withSyscalls bool) string {
	users, groups, paths := map[string]bool{}, map[string]bool{}, map[string]bool{}
	syscalls := map[string]map[string]bool{}
	for _, l := range lines {
		k := parseAuditK(l, auditSource)
		if !k.ok {
			continue
		}
		if withSyscalls && k.namedSyscalls && k.list == "exit" {
			arch := ""
			if k.arch != nil {
				arch = k.arch.raw
			}
			if arch == "" || auditArchTokenRe.MatchString(arch) {
				for _, sc := range k.syscalls {
					if sc != "all" && auditSyscallNameRe.MatchString(sc) {
						if syscalls[arch] == nil {
							syscalls[arch] = map[string]bool{}
						}
						syscalls[arch][sc] = true
					}
				}
			}
		}
		for _, f := range k.filters {
			if !auditNameRe.MatchString(f.raw) || f.raw == "unset" {
				continue
			}
			if auditUIDFields[f.name] {
				users[f.raw] = true
			} else if auditGIDFields[f.name] {
				groups[f.raw] = true
			}
		}
		if k.watch && k.target.value != "" && !strings.ContainsAny(k.target.value, "\t\n") {
			paths[k.target.value] = true
		}
	}
	var b strings.Builder
	b.WriteString(`printf 'machine\t%s\n' "$(uname -m 2>/dev/null)"; `)
	b.WriteString(`printf 'auditctl\t%s\n' "$(auditctl -v 2>&1 | head -n 1)"; `)
	for _, n := range sortedKeys(users) {
		fmt.Fprintf(&b, `e=$(getent -s files passwd %s) && printf 'uid\t%%s\t%%s\n' %s "$(printf '%%s' "$e" | cut -d: -f3)"; `,
			shellQuote(n), shellQuote(n))
	}
	for _, n := range sortedKeys(groups) {
		fmt.Fprintf(&b, `e=$(getent -s files group %s) && printf 'gid\t%%s\t%%s\n' %s "$(printf '%%s' "$e" | cut -d: -f3)"; `,
			shellQuote(n), shellQuote(n))
	}
	for _, p := range sortedKeys(paths) {
		fmt.Fprintf(&b, `p=%s; if [ -L "$p" ]; then k=symlink; elif [ -d "$p" ]; then k=dir; `+
			`elif [ -e "$p" ]; then k=other; else k=missing; fi; printf 'path\t%%s\t%%s\n' "$p" "$k"; `, shellQuote(p))
	}
	if len(syscalls) > 0 {
		// The arch auditctl looks a name up in: b64 and a rule with no arch
		// are the machine's own; b32 is its 32-bit arch. A lookup that fails,
		// or prints anything but one number (several lines, a word), prints
		// nothing, so the name stays unresolved.
		b.WriteString(`m=$(uname -m 2>/dev/null); case "$m" in x86_64) a64=x86_64; a32=i386;; ` +
			`aarch64) a64=aarch64; a32=arm;; *) a64=; a32=;; esac; ` +
			`sc() { [ -n "$2" ] || return 0; n=$(ausyscall "$2" "$3" --exact 2>/dev/null) || return 0; ` +
			`case "$n" in ''|*[!0-9]*) return 0;; esac; printf 'sc\t%s\t%s\t%s\n' "$1" "$3" "$n"; }; `)
		archs := map[string]bool{}
		for a := range syscalls {
			archs[a] = true
		}
		for _, arch := range sortedKeys(archs) {
			lookup := shellQuote(arch)
			switch arch {
			case "", "b64":
				lookup = `"$a64"`
			case "b32":
				lookup = `"$a32"`
			}
			for _, sc := range sortedKeys(syscalls[arch]) {
				fmt.Fprintf(&b, "sc %s %s %s; ", shellQuote(arch), lookup, shellQuote(sc))
			}
		}
	}
	b.WriteString("true")
	return b.String()
}

// ParseAuditTarget reads AuditTargetProbe output. Lines it does not
// recognize are ignored, so a missing fact stays unresolved.
func ParseAuditTarget(out string) *AuditTarget {
	t := &AuditTarget{UIDs: map[string]int64{}, GIDs: map[string]int64{}, Paths: map[string]AuditPathKind{},
		Syscalls: map[string]map[string]int64{}}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		switch {
		case len(f) == 2 && f[0] == "machine":
			t.Machine = strings.TrimSpace(f[1])
		case len(f) == 2 && f[0] == "auditctl":
			if m := auditVersionRe.FindString(f[1]); m != "" {
				t.AuditctlVersion = m
			}
		case len(f) == 3 && (f[0] == "uid" || f[0] == "gid"):
			v := strings.TrimSpace(f[2])
			if !auditDecimalRe.MatchString(v) {
				continue
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			if f[0] == "uid" {
				t.UIDs[f[1]] = n
			} else {
				t.GIDs[f[1]] = n
			}
		case len(f) == 4 && f[0] == "sc":
			v := strings.TrimSpace(f[3])
			if !auditDecimalRe.MatchString(v) || !auditSyscallNameRe.MatchString(f[2]) {
				continue
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			if t.Syscalls[f[1]] == nil {
				t.Syscalls[f[1]] = map[string]int64{}
			}
			t.Syscalls[f[1]][f[2]] = n
		case len(f) == 3 && f[0] == "path":
			switch k := AuditPathKind(strings.TrimSpace(f[2])); k {
			case AuditPathDir, AuditPathOther, AuditPathSymlink, AuditPathMissing:
				t.Paths[f[1]] = k
			}
		}
	}
	return t
}

// ReadAuditTarget runs AuditTargetProbe for lines on the target. A transport
// error or a non-zero exit is an error: the caller cannot resolve anything.
func ReadAuditTarget(ctx context.Context, transport api.Transport, lines []string) (*AuditTarget, error) {
	return readAuditTarget(ctx, transport, auditTargetProbe(lines, true))
}

// readAuditCoverageTarget reads the facts coverage needs, which do not
// include syscall numbers: coverage compares a listing's names with the
// requirement's names.
func readAuditCoverageTarget(ctx context.Context, transport api.Transport, lines []string) (*AuditTarget, error) {
	return readAuditTarget(ctx, transport, auditTargetProbe(lines, false))
}

func readAuditTarget(ctx context.Context, transport api.Transport, probe string) (*AuditTarget, error) {
	res, err := transport.Run(ctx, probe)
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, fmt.Errorf("audit target probe exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return ParseAuditTarget(res.Stdout), nil
}

// auditSide says who built the line: a rules.d source line, which auditctl
// will turn into a kernel rule, or a line auditctl -l printed from one.
type auditSide int

const (
	auditSource auditSide = iota
	auditLoaded
)

type auditFilter struct{ name, op, raw string }

// auditTargetField is the path= or dir= field of a rule, or the one a -w
// makes. kind is "path", "dir", or "" when it depends on facts not known.
type auditTargetField struct {
	kind, value string
}

// auditK is one rule line split into the parts the kernel compares.
type auditK struct {
	ok            bool
	side          auditSide
	action, list  string
	watch         bool // written as -w
	hasTarget     bool
	target        auditTargetField
	perm          string // as written; "" when absent
	arch          *auditFilter
	filters       []auditFilter // every -F but key, arch, path, dir, perm
	cmps          []string      // canonical -C comparisons
	keys          []string      // in order
	syscalls      []string      // as written, in order
	namedSyscalls bool
	// unmodeled names a key, path, dir or perm field written with an
	// operator other than "=". auditctl -l prints those fields with "=", and
	// a watch with no operator at all. go-libaudit's printer drops them too,
	// so no listing shows them.
	unmodeled string
	// repeated names a field the line gives twice: arch, perm, the path or
	// dir target, the action or the list. The parser keeps one value of
	// each, so the line cannot be compared with them. repeatedKinds holds
	// every such field.
	repeated      string
	repeatedKinds map[string]bool
	// netlink says the line came from auditnl.RuleText, whose syscall names
	// are go-libaudit's table, not the host's.
	netlink bool
}

// parseAuditK splits a line. Watches are read as the syscall rule auditctl
// builds for them: always,exit over all syscalls with a path or dir field
// and a perm field.
func parseAuditK(line string, side auditSide) auditK {
	k := auditK{side: side}
	fields := splitAuditFlags(strings.Fields(line))
	isSyscall := false
	// The kernel ANDs every field, but arch, perm, the path or dir target,
	// the action and the list are kept as one value each. A second one would
	// overwrite the first, so a repeat makes the line Unresolved instead.
	seen := map[string]int{}
	once := func(what string) {
		if seen[what]++; seen[what] == 2 {
			if k.repeatedKinds == nil {
				k.repeatedKinds = map[string]bool{}
			}
			k.repeatedKinds[what] = true
			if k.repeated == "" {
				k.repeated = "a repeated " + what + " field, which this comparison does not model"
			}
		}
	}
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		next := ""
		if i+1 < len(fields) {
			next = fields[i+1]
		}
		switch f {
		case "-w":
			once("path or dir")
			k.watch, k.hasTarget = true, true
			// auditctl drops a -w path's trailing slashes before it builds
			// the rule (captured: -w /etc/sudoers.d/ lists without one). A
			// listed -w keeps its slash: only a dir= rule prints one.
			k.target.value = next
			if side == auditSource {
				k.target.value = canonAuditPath(next)
			}
			i++
		case "-p":
			once("perm")
			k.perm = next
			i++
		case "-a", "-A":
			isSyscall = true
			// libaudit reads the action and list names without regard to case.
			for _, part := range strings.Split(strings.ToLower(next), ",") {
				switch part {
				case "always", "never":
					once("action")
					k.action = part
				default:
					once("list")
					k.list = part
				}
			}
			i++
		case "-S":
			k.namedSyscalls = true
			// Syscall names are looked up without regard to case, and an
			// alias is read as the name it stands for.
			for _, sc := range strings.Split(strings.ToLower(next), ",") {
				if a, ok := auditSyscallAlias[sc]; ok {
					sc = a
				}
				if sc != "" {
					k.syscalls = append(k.syscalls, sc)
				}
			}
			i++
		case "-F":
			i++
			name, op, value := splitAuditField(next)
			if op != "=" && (name == "key" || name == "path" || name == "dir" || name == "perm") && k.unmodeled == "" {
				k.unmodeled = "a " + name + op + " field, whose operator no listing shows"
			}
			switch name {
			case "key":
				k.keys = append(k.keys, splitAuditKeys(value)...)
			case "path", "dir":
				once("path or dir")
				k.hasTarget = true
				k.target = auditTargetField{kind: name, value: value}
			case "perm":
				once("perm")
				k.perm = value
			case "arch":
				once("arch")
				k.arch = &auditFilter{name: name, op: op, raw: strings.ToLower(value)}
			default:
				k.filters = append(k.filters, auditFilter{name: name, op: op, raw: value})
			}
		case "-C":
			k.cmps = append(k.cmps, canonAuditCompare(auditCompareFieldNames(next)))
			i++
		case "-k":
			k.keys = append(k.keys, splitAuditKeys(next)...)
			i++
		}
	}
	switch {
	case k.watch && !isSyscall && k.target.value != "":
		k.ok, k.action, k.list = true, "always", "exit"
		if k.perm == "" {
			k.perm = "rwxa"
		}
	case isSyscall && !k.watch && k.action != "" && k.list != "":
		k.ok = true
	}
	return k
}

// splitAuditKeys splits a key value on AUDIT_KEY_SEPARATOR (\x01). The
// kernel stores a rule's keys as one string joined by it, and a netlink
// listing returns that string whole, where auditctl -l prints one key flag
// per key. Splitting both sides the same way compares the two forms.
func splitAuditKeys(v string) []string { return strings.Split(v, "\x01") }

// auditSyscallAlias maps a syscall name to the one libaudit gives the same
// number. libaudit 3.1.2's i386, x86_64, arm and aarch64 tables have one such
// pair: madvise1 is madvise (219 on i386).
var auditSyscallAlias = map[string]string{"madvise1": "madvise"}

// auditFieldAlias maps a field name to the one libaudit builds the same
// field from: loginuid is auid (both AUDIT_LOGINUID).
var auditFieldAlias = map[string]string{"loginuid": "auid"}

// auditFieldName is a -F or -C field name as libaudit reads it: without
// regard to case, and with aliases resolved.
func auditFieldName(name string) string {
	name = strings.ToLower(name)
	if a, ok := auditFieldAlias[name]; ok {
		return a
	}
	return name
}

// auditCompareFieldNames rewrites the two field names of a -C comparison as
// libaudit reads them.
func auditCompareFieldNames(tok string) string {
	for _, op := range []string{"!=", "="} {
		if l, r, ok := strings.Cut(tok, op); ok {
			return auditFieldName(l) + op + auditFieldName(r)
		}
	}
	return tok
}

// splitAuditField splits a -F token into name, operator and value. The
// name is read as libaudit reads it (auditFieldName).
func splitAuditField(tok string) (string, string, string) {
	idx := strings.IndexAny(tok, "!=<>&")
	if idx <= 0 {
		return auditFieldName(tok), "", ""
	}
	name, rest := auditFieldName(tok[:idx]), tok[idx:]
	for _, o := range []string{"!=", ">=", "<=", "&=", "=", ">", "<", "&"} {
		if strings.HasPrefix(rest, o) {
			return name, o, strings.TrimPrefix(rest, o)
		}
	}
	return name, "", rest
}

// targetKind is the kernel field type of the rule's path: what the line
// says for path= and dir=, and for a source -w what stat says auditctl will
// pick: a directory gives dir; a regular file or a missing path gives path
// (captured: -w and path= on a missing path are one rule). A symlink, an
// unprobed path, and a -w in a listing give "": auditctl -l prints path=
// and dir= the same way, on a directory and on a regular file alike
// (captured: dir= on /etc/shadow lists as -w /etc/shadow).
func (k auditK) targetKind(t *AuditTarget) string {
	if !k.watch {
		return k.target.kind
	}
	if k.side == auditLoaded {
		// dir= keeps a trailing slash and -w and path= never do (captured:
		// dir=/etc/sudoers.d/ lists as -w /etc/sudoers.d/), so a slash
		// shows a dir field. Without one the listing cannot tell.
		if strings.HasSuffix(k.target.value, "/") && len(k.target.value) > 1 {
			return "dir"
		}
		return ""
	}
	if t == nil {
		return ""
	}
	switch t.Paths[k.target.value] {
	case AuditPathDir:
		return "dir"
	case AuditPathOther, AuditPathMissing:
		return "path"
	}
	return ""
}

// cleanAuditPath reports whether p is absolute and already in clean form,
// so two clean paths that differ name different files.
func cleanAuditPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p
}

// maskKind is how much is known about a rule's syscall mask.
type maskKind int

const (
	maskAll        maskKind = iota // every syscall
	maskSet                        // exactly these names
	maskNone                       // not a syscall list
	maskUnresolved                 // depends on facts not known
)

type auditMask struct {
	kind  maskKind
	set   map[string]bool
	spell string // what decided an unresolved mask, for exact-spelling equality
	// nums is the set as syscall numbers, when ausyscall on the host
	// resolved every name for the rule's arch; nil otherwise.
	nums map[int64]bool
	// foreign marks names from go-libaudit's syscall table (a netlink
	// rendering): a name that differs from the host's is not a measured
	// difference.
	foreign bool
}

// withNumbers fills m.nums from the host's ausyscall answers for the arch
// token, when every name resolves.
func (m auditMask) withNumbers(k auditK, t *AuditTarget) auditMask {
	if m.kind != maskSet || t == nil {
		return m
	}
	arch := ""
	if k.arch != nil {
		if k.arch.op != "=" {
			return m
		}
		arch = k.arch.raw
	}
	table := t.Syscalls[arch]
	nums := map[int64]bool{}
	for sc := range m.set {
		n, ok := table[sc]
		if !ok {
			return m
		}
		nums[n] = true
	}
	m.nums = nums
	return m
}

func (k auditK) mask(t *AuditTarget) auditMask {
	if k.list != "exit" {
		return auditMask{kind: maskNone, spell: strings.Join(k.syscalls, ",")}
	}
	if k.watch {
		return auditMask{kind: maskAll}
	}
	if k.namedSyscalls {
		set := map[string]bool{}
		for _, sc := range k.syscalls {
			if auditDecimalRe.MatchString(sc) {
				return auditMask{kind: maskUnresolved, spell: "-S " + strings.Join(k.syscalls, ",")}
			}
			set[sc] = true
		}
		if set["all"] {
			if len(set) == 1 {
				return auditMask{kind: maskAll}
			}
			return auditMask{kind: maskUnresolved, spell: "-S " + strings.Join(sortedKeys(set), ",")}
		}
		if k.side == auditSource && k.perm != "" {
			// auditctl loads an explicit list with a perm filter as the list
			// joined with the perm class list (captured: -S execve with
			// perm=wa lists the wa class plus execve; -S chmod lists the wa
			// class alone).
			class, ok := k.classSet(t)
			if !ok {
				return auditMask{kind: maskUnresolved, spell: "-S+perm " + strings.Join(sortedKeys(set), ",")}
			}
			for sc := range class {
				set[sc] = true
			}
		}
		if k.side == auditSource && k.perm != "" {
			// Joined with the class list, whose names the probe does not
			// look up, so the set stays in names.
			return auditMask{kind: maskSet, set: set}
		}
		m := auditMask{kind: maskSet, set: set, foreign: k.netlink}
		return m.withNumbers(k, t)
	}
	if k.side == auditLoaded {
		return auditMask{kind: maskUnresolved, spell: "listed without -S"}
	}
	if k.hasTarget && k.perm != "" {
		if k.arch == nil {
			// A path= or dir= rule with no arch loads as the watch -w makes
			// (captured: "Rule exists" against -w), over all syscalls.
			return auditMask{kind: maskAll}
		}
		if set, ok := k.classSet(t); ok {
			return auditMask{kind: maskSet, set: set}
		}
		return auditMask{kind: maskUnresolved, spell: "class " + k.arch.op + k.arch.raw + " " + k.perm}
	}
	return auditMask{kind: maskUnresolved, spell: "no -S"}
}

// classSet is the captured perm class list for the rule's equality arch and
// perm on target t, or false when the arch, the perm or the target is not
// one that was captured.
func (k auditK) classSet(t *AuditTarget) (map[string]bool, bool) {
	if k.arch == nil || k.arch.op != "=" || k.perm == "" {
		return nil, false
	}
	a, ok := k.resolvedArch(t)
	if !ok {
		return nil, false
	}
	list, ok := auditPermClassFor(t, map[string]string{"x86_64": "b64", "i386": "b32"}[a], canonAuditPerm(k.perm))
	if !ok {
		return nil, false
	}
	set := map[string]bool{}
	for _, sc := range list {
		set[sc] = true
	}
	return set, true
}

// resolvedArch is the kernel arch the rule's arch token names on target t.
func (k auditK) resolvedArch(t *AuditTarget) (string, bool) {
	if k.arch == nil || t == nil {
		return "", false
	}
	if auditArchNames[k.arch.raw] {
		return k.arch.raw, true
	}
	a, ok := auditArchByMachine[t.Machine][k.arch.raw]
	return a, ok
}

// resolveAuditValue returns a filter value as the 32-bit number the kernel
// stores, when the target resolves it, so two spellings of one value
// compare equal. libaudit stores a value in a u32, so -13 and 4294967283
// are one value (built byte-identical by libaudit 3.1.2). A number that
// does not fit a u32 field either way, below -2^31 or above 2^32-1, is left
// unresolved: what libaudit does with it was not measured.
func resolveAuditValue(f auditFilter, t *AuditTarget) (int64, bool) {
	n, ok := resolveAuditNumber(f, t)
	if !ok || n < -(1<<31) || n > (1<<32)-1 {
		return 0, false
	}
	if n < 0 {
		n += 1 << 32
	}
	return n, true
}

func resolveAuditNumber(f auditFilter, t *AuditTarget) (int64, bool) {
	v := f.raw
	if auditUIDFields[f.name] || auditGIDFields[f.name] {
		if v == "unset" {
			return -1, true
		}
		if auditDecimalRe.MatchString(v) {
			n, err := strconv.ParseInt(v, 10, 64)
			return n, err == nil
		}
		if t == nil {
			return 0, false
		}
		m := t.UIDs
		if auditGIDFields[f.name] {
			m = t.GIDs
		}
		n, ok := m[v]
		return n, ok
	}
	if f.name == "exit" && len(v) > 2 && strings.EqualFold(v[:2], "-E") {
		n, ok := auditErrno[strings.ToUpper(v[1:])]
		switch {
		case !ok:
			return 0, false
		case n <= 34:
			// asm-generic errno-base numbers, the same on every Linux arch.
			return -n, true
		case t != nil && auditArchByMachine[t.Machine] != nil:
			return -n, true
		}
		return 0, false
	}
	if auditDecimalRe.MatchString(v) {
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// idAcc collects the comparison of two rules part by part. In cover mode it
// compares a requirement with a listed rule for coverage: there a field the
// listing lacks or adds is a real difference in the loaded rule, not a
// question of what auditctl may build. In both modes perm letters compare as
// sets that must be equal, in any order.
type idAcc struct {
	distinct   string
	unresolved []string
	cover      bool
}

// oneSided records a field present on one side only.
func (a *idAcc) oneSided(why string) {
	if a.cover {
		a.differ(why)
	} else {
		a.unsure(why)
	}
}

func (a *idAcc) differ(why string) {
	if a.distinct == "" {
		a.distinct = why
	}
}

func (a *idAcc) unsure(why string) { a.unresolved = append(a.unresolved, why) }

func (a *idAcc) result() (AuditIdentity, string) {
	switch {
	case a.distinct != "":
		return AuditDistinct, a.distinct
	case len(a.unresolved) > 0:
		return AuditUnresolved, strings.Join(a.unresolved, "; ")
	}
	return AuditSame, "every part matches"
}

// AuditRuleIdentity reports whether a and b, both rules.d source lines that
// auditctl will load on target t, build the same kernel rule. The kernel
// compares action, list, every field in order, and the syscall mask, so
// Distinct needs one part that provably differs; anything that may differ
// only through a fact not known is Unresolved. Comparing fields as a set
// rather than in order can only turn a Distinct into a Same, the safe
// direction for a guard. Lines that are not rules return Distinct.
func AuditRuleIdentity(a, b string, t *AuditTarget) (AuditIdentity, string) {
	return auditIdentity(parseAuditK(a, auditSource), parseAuditK(b, auditSource), t)
}

// AuditLoadedIdentity compares a source line with a line auditctl -l (or
// its netlink equivalent) printed: is the listed rule the one auditctl
// built from the source line?
func AuditLoadedIdentity(source, listed string, t *AuditTarget) (AuditIdentity, string) {
	return auditIdentity(parseAuditK(source, auditSource), parseAuditK(listed, auditLoaded), t)
}

// AuditLoadedAmong reports whether a rule among lines may be loaded, judged
// against a listing of the loaded rules: auditctl -l lines, or netlink rules
// rendered by auditnl.RuleText. It returns the first line whose identity
// with a listed rule is Same, else the first that is Unresolved, else
// AuditDistinct. Lines that are not rules, such as -e 2, and the "No rules"
// line are not compared. A listed line the parser cannot read makes the
// answer Unresolved at best, since it may be the rule. Only listed rules with the line's keys are
// compared, since a key difference always makes two rules distinct; the
// host facts are read for those alone. A failure to read the facts is an
// error.
func AuditLoadedAmong(ctx context.Context, transport api.Transport, lines, listed []string, netlink bool) (string, AuditIdentity, string, error) {
	type pair struct{ line, row string }
	var pairs []pair
	probe := map[string]bool{}
	var probeLines []string
	add := func(l string) {
		if !probe[l] {
			probe[l] = true
			probeLines = append(probeLines, l)
		}
	}
	var unsureLine, unsureWhy string
	for _, l := range lines {
		src := parseAuditK(l, auditSource)
		if !src.ok {
			continue
		}
		for _, r := range listed {
			r = strings.TrimSpace(r)
			if r == "" || r == "No rules" {
				continue
			}
			got := parseAuditK(r, auditLoaded)
			if !got.ok {
				// A listed line the parser cannot read may be the rule.
				if unsureLine == "" {
					unsureLine, unsureWhy = l, fmt.Sprintf("the listed line %q could not be read", r)
				}
				continue
			}
			if strings.Join(src.keys, "\x01") != strings.Join(got.keys, "\x01") {
				continue
			}
			pairs = append(pairs, pair{l, r})
			add(l)
			add(r)
		}
	}
	if len(pairs) == 0 {
		if unsureLine != "" {
			return unsureLine, AuditUnresolved, unsureWhy, nil
		}
		return "", AuditDistinct, "", nil
	}
	target, err := ReadAuditTarget(ctx, transport, probeLines)
	if err != nil {
		return "", AuditDistinct, "", fmt.Errorf("read the host facts needed to compare audit rules: %w", err)
	}
	for _, p := range pairs {
		got := parseAuditK(p.row, auditLoaded)
		got.netlink = netlink
		switch id, why := auditIdentity(parseAuditK(p.line, auditSource), got, target); id {
		case AuditSame:
			return p.line, AuditSame, "", nil
		case AuditUnresolved:
			if unsureLine == "" {
				unsureLine, unsureWhy = p.line, why
			}
		}
	}
	if unsureLine != "" {
		return unsureLine, AuditUnresolved, unsureWhy, nil
	}
	return "", AuditDistinct, "", nil
}

// auditRuleFlags are the auditctl options a rule line may carry. Any other
// option in a line, such as -b 8192, -D or -e 2 written after a rule,
// auditctl also acts on when it loads the line.
var auditRuleFlags = map[string]bool{"-a": true, "-A": true, "-w": true, "-p": true, "-k": true, "-F": true, "-S": true, "-C": true}

// AuditLineControlFlag returns the first option in an audit rule line that
// is not a rule option, or "". auditctl does not reject one: -b inside a
// rule line sets the backlog and adds the rule (auditctl.c, every version
// from 3.1.2 to 4.0.3, checks no option count for -b).
func AuditLineControlFlag(line string) string {
	fields := splitAuditFlags(strings.Fields(line))
	takesArg := map[string]bool{"-a": true, "-A": true, "-w": true, "-p": true, "-k": true, "-F": true, "-S": true, "-C": true}
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if takesArg[f] {
			i++
			continue
		}
		if strings.HasPrefix(f, "-") && !auditRuleFlags[f] {
			return f
		}
	}
	return ""
}

// AuditRuleList returns the filter list a source line names, such as
// "exit" or "exclude", lower-cased as libaudit reads it. ok is false for a
// line that is not an audit rule, such as a control line (-e 2, -D, -b).
func AuditRuleList(line string) (list string, ok bool) {
	k := parseAuditK(line, auditSource)
	return k.list, k.ok
}

func auditIdentity(a, b auditK, t *AuditTarget) (AuditIdentity, string) {
	if !a.ok || !b.ok {
		return AuditDistinct, "not an audit rule"
	}
	var acc idAcc
	switch {
	case a.action != b.action:
		acc.differ(fmt.Sprintf("action %s vs %s", a.action, b.action))
	case a.list != b.list && (a.list == "entry" || b.list == "entry") && (a.list == "exit" || b.list == "exit"):
		// auditctl may rewrite a deprecated entry rule as an exit rule; not
		// measured.
		acc.unsure("an entry rule and an exit rule")
	case a.list != b.list:
		acc.differ(fmt.Sprintf("list %s vs %s", a.list, b.list))
	}
	compareAuditKeys(&acc, a.keys, b.keys)
	compareAuditBody(&acc, a, b, t)
	compareAuditMask(&acc, a.mask(t), b.mask(t), t)
	return acc.result()
}

// compareAuditKeys compares the key lists as the kernel compares the one key
// string auditctl builds from them. Any difference makes the rules distinct:
// captured on RHEL 10.2 and Rocky 9.8, two rules that differ only in key load
// twice, for syscall rules, for watches on a file and on a directory, for keys
// in another order, and for a key on one side only.
func compareAuditKeys(acc *idAcc, ka, kb []string) {
	if strings.Join(ka, "\x01") != strings.Join(kb, "\x01") {
		acc.differ(fmt.Sprintf("keys [%s] vs [%s]", strings.Join(ka, ","), strings.Join(kb, ",")))
	}
}

// compareAuditBody compares everything but action, list, keys and mask.
func compareAuditBody(acc *idAcc, a, b auditK, t *AuditTarget) {
	for _, k := range []auditK{a, b} {
		if k.unmodeled != "" {
			acc.unsure(k.unmodeled)
		}
		if k.repeated != "" {
			acc.unsure(k.repeated)
		}
	}
	// The path or dir field.
	switch {
	case a.hasTarget != b.hasTarget:
		acc.oneSided("a path or dir field on one side only")
	case a.hasTarget:
		va, vb := a.target.value, b.target.value
		ka, kb := a.targetKind(t), b.targetKind(t)
		switch {
		case va == vb:
		case ka == "dir" && kb == "dir" && strings.TrimSuffix(va, "/") == strings.TrimSuffix(vb, "/"):
			// Captured: dir=/etc/sudoers.d and dir=/etc/sudoers.d/ load
			// twice, so for identity they differ. Whether they record the
			// same events is not measured, so for coverage it is unknown.
			if acc.cover {
				acc.unsure(fmt.Sprintf("dir %s and %s differ only by a trailing slash", va, vb))
			} else {
				acc.differ(fmt.Sprintf("dir %s vs %s", va, vb))
			}
		case cleanAuditPath(va) && cleanAuditPath(vb):
			acc.differ(fmt.Sprintf("paths %s vs %s", va, vb))
		default:
			acc.unsure(fmt.Sprintf("paths %q and %q are not both in clean form", va, vb))
		}
		switch {
		case ka != "" && kb != "" && ka != kb && !acc.cover && (a.watch && a.side == auditSource) != (b.watch && b.side == auditSource) &&
			(a.side == auditLoaded || b.side == auditLoaded):
			// A source -w takes its field type from the path's type now, but
			// auditctl chose path= or dir= from the path's type when it built
			// the loaded rule, at boot. The path may have been created,
			// removed or replaced since, so a type mismatch does not show the
			// loaded rule is another rule.
			acc.unsure(fmt.Sprintf("a %s field vs a %s field, and the path's type when the rule loaded is not known", ka, kb))
		case ka != "" && kb != "" && ka != kb:
			acc.differ(fmt.Sprintf("a %s field vs a %s field", ka, kb))
		case ka == "" || kb == "":
			acc.unsure(auditWatchKindUnknown)
		}
	}

	// The perm field.
	switch {
	case a.perm == "" && b.perm == "":
	case a.perm == "" || b.perm == "":
		acc.oneSided("a perm on one side only")
	default:
		ca, cb := canonAuditPerm(a.perm), canonAuditPerm(b.perm)
		valid := strings.Trim(a.perm, "rwxa") == "" && strings.Trim(b.perm, "rwxa") == ""
		switch {
		case valid && ca != cb:
			acc.differ(fmt.Sprintf("perm %s vs %s", ca, cb))
		case !valid && a.perm != b.perm:
			acc.unsure(fmt.Sprintf("perm written %q and %q", a.perm, b.perm))
		}
	}

	// The arch field.
	switch {
	case a.arch == nil && b.arch == nil:
	case a.arch == nil || b.arch == nil:
		// Captured: -S chown with no arch and with arch=b64 load twice, and
		// auditctl lists the first with no arch; it adds none.
		acc.differ("an arch on one side only")
	case a.arch.op != b.arch.op:
		acc.differ(fmt.Sprintf("arch operator %s vs %s", a.arch.op, b.arch.op))
	default:
		ra, oka := a.resolvedArch(t)
		rb, okb := b.resolvedArch(t)
		bits := map[string]bool{"b64": true, "b32": true}
		switch {
		case oka && okb && ra != rb:
			acc.differ(fmt.Sprintf("arch %s vs %s", a.arch.raw, b.arch.raw))
		case bits[a.arch.raw] && bits[b.arch.raw] && a.arch.raw != b.arch.raw:
			// The machine's 64-bit and 32-bit arches differ on any machine.
			acc.differ(fmt.Sprintf("arch %s vs %s", a.arch.raw, b.arch.raw))
		case oka && okb:
		case a.arch.raw != b.arch.raw:
			acc.unsure(fmt.Sprintf("arch %s and %s are not resolved on this machine", a.arch.raw, b.arch.raw))
		}
	}

	compareAuditFilters(acc, a.filters, b.filters, t)

	// -C comparisons pass through (captured: -C euid!=uid lists as -C uid!=euid).
	ca, cb := append([]string(nil), a.cmps...), append([]string(nil), b.cmps...)
	sort.Strings(ca)
	sort.Strings(cb)
	if strings.Join(ca, " ") != strings.Join(cb, " ") {
		acc.differ(fmt.Sprintf("comparisons %v vs %v", ca, cb))
	}
}

func compareAuditFilters(acc *idAcc, fa, fb []auditFilter, t *AuditTarget) {
	byName := func(fs []auditFilter) map[string][]auditFilter {
		m := map[string][]auditFilter{}
		for _, f := range fs {
			m[f.name] = append(m[f.name], f)
		}
		return m
	}
	ma, mb := byName(fa), byName(fb)
	names := map[string]bool{}
	for n := range ma {
		names[n] = true
	}
	for n := range mb {
		names[n] = true
	}
	for _, n := range sortedKeys(names) {
		la, lb := ma[n], mb[n]
		if len(la) != len(lb) {
			if auditPassThrough[n] {
				acc.differ(fmt.Sprintf("%d %s filter(s) vs %d", len(la), n, len(lb)))
			} else {
				acc.oneSided(fmt.Sprintf("%d %s filter(s) vs %d", len(la), n, len(lb)))
			}
			continue
		}
		opsOf := func(l []auditFilter) []string {
			out := make([]string, len(l))
			for i, f := range l {
				out[i] = f.op
			}
			sort.Strings(out)
			return out
		}
		if strings.Join(opsOf(la), " ") != strings.Join(opsOf(lb), " ") {
			acc.differ(fmt.Sprintf("%s operators %v vs %v", n, opsOf(la), opsOf(lb)))
			continue
		}
		compareAuditValues(acc, n, la, lb, t)
	}
}

// compareAuditValues compares one field's values, grouped by operator.
func compareAuditValues(acc *idAcc, name string, la, lb []auditFilter, t *AuditTarget) {
	group := func(l []auditFilter) map[string][]auditFilter {
		m := map[string][]auditFilter{}
		for _, f := range l {
			m[f.op] = append(m[f.op], f)
		}
		return m
	}
	ga, gb := group(la), group(lb)
	ops := make([]string, 0, len(ga))
	for op := range ga {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		xa, xb := ga[op], gb[op]
		nums := func(l []auditFilter) ([]int64, bool) {
			out := make([]int64, 0, len(l))
			for _, f := range l {
				n, ok := resolveAuditValue(f, t)
				if !ok {
					return nil, false
				}
				out = append(out, n)
			}
			sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
			return out, true
		}
		raws := func(l []auditFilter) string {
			out := make([]string, len(l))
			for i, f := range l {
				out[i] = f.raw
			}
			sort.Strings(out)
			return strings.Join(out, " ")
		}
		na, oka := nums(xa)
		nb, okb := nums(xb)
		switch {
		case oka && okb:
			if fmt.Sprint(na) != fmt.Sprint(nb) {
				acc.differ(fmt.Sprintf("%s%s values %v vs %v", name, op, na, nb))
			}
		case raws(xa) == raws(xb):
		default:
			acc.unsure(fmt.Sprintf("%s%s values %s and %s are not resolved", name, op, raws(xa), raws(xb)))
		}
	}
}

func compareAuditMask(acc *idAcc, ma, mb auditMask, t *AuditTarget) {
	concrete := func(m auditMask) bool { return m.kind == maskAll || m.kind == maskSet }
	numbered := func(m auditMask) bool { return m.kind == maskAll || m.nums != nil }
	switch {
	case numbered(ma) && numbered(mb):
		// Syscall numbers from ausyscall on the host: a different set of
		// numbers is a different kernel mask on any audit version. A named
		// set is never every syscall.
		if ma.kind != mb.kind {
			acc.differ("different syscall masks (numbers from ausyscall)")
		} else if ma.kind == maskSet && fmt.Sprint(sortedInts(ma.nums)) != fmt.Sprint(sortedInts(mb.nums)) {
			acc.differ("different syscall masks (numbers from ausyscall)")
		}
	case concrete(ma) && concrete(mb):
		if ma.kind == mb.kind && (ma.kind == maskAll || sameStringSet(ma.set, mb.set)) {
			return
		}
		// Names map to syscall numbers per arch, so a difference is
		// trusted only where the names were captured, and only in names the
		// host's own tools printed.
		switch {
		case ma.foreign || mb.foreign:
			acc.unsure("syscall masks differ by name, and one side's names are go-libaudit's, not the host's")
		case t.measured():
			acc.differ("different syscall masks")
		default:
			acc.unsure("syscall masks differ by name, outside the measured arch and versions")
		}
	case ma.kind == mb.kind && ma.spell == mb.spell:
	default:
		acc.unsure("the loaded syscall mask is not known")
	}
}

func sameStringSet(a, b map[string]bool) bool {
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

// withoutRepeats returns copies of a and b in which every field either
// repeats takes a's value on both sides, and neither is marked repeated, so a
// comparison sees only their other fields.
func withoutRepeats(a, b auditK) (auditK, auditK) {
	kinds := map[string]bool{}
	for k := range a.repeatedKinds {
		kinds[k] = true
	}
	for k := range b.repeatedKinds {
		kinds[k] = true
	}
	for k := range kinds {
		switch k {
		case "arch":
			b.arch = a.arch
		case "perm":
			b.perm = a.perm
		case "path or dir":
			b.hasTarget, b.target, b.watch = a.hasTarget, a.target, a.watch
		case "action":
			b.action = a.action
		case "list":
			b.list = a.list
		}
	}
	a.repeated, b.repeated = "", ""
	a.repeatedKinds, b.repeatedKinds = nil, nil
	return a, b
}

// AuditCoverage is the answer to the compliance question.
type AuditCoverage int

const (
	AuditNotCovered AuditCoverage = iota
	AuditCovered
	// AuditCoverAmbiguous: the listing cannot show whether the requirement
	// is met, for example a -w line that may be a path or a dir field.
	AuditCoverAmbiguous
)

// auditRuleCovers reports whether the loaded rule got, as auditctl -l
// printed it, records every event the requirement req asks for. The policy:
// the same action and list, the same filters after resolution, the same
// path or dir field and perm, and, for an always rule, a syscall mask that
// contains the requirement's; a never rule needs the same mask. Keys are
// left to the caller. Rule order is not modeled: a never rule listed ahead
// of a covering always rule still suppresses its records.
func auditRuleCovers(req, got auditK, t *AuditTarget) (AuditCoverage, string) {
	if !req.ok || !got.ok {
		return AuditNotCovered, "not an audit rule"
	}
	// The kernel requires every occurrence of a repeated field to match
	// (measured for perm on RHEL 10.2: perm=r with perm=w recorded neither a
	// read nor a write), so the field
	// compared on its last value alone could call a covering rule a miss or
	// a miss covered. Compare everything else with that field taken as
	// equal: a difference elsewhere is a miss, and otherwise the answer
	// turns on the repeated field, which is not decided.
	if req.repeated != "" || got.repeated != "" {
		why := req.repeated
		if why == "" {
			why = got.repeated
		}
		r, g := withoutRepeats(req, got)
		if c, w := auditRuleCovers(r, g, t); c == AuditNotCovered {
			return c, w
		}
		return AuditCoverAmbiguous, why
	}
	if req.action != got.action || req.list != got.list {
		return AuditNotCovered, "different action or list"
	}
	acc := idAcc{cover: true}
	compareAuditBody(&acc, req, got, t)
	if acc.distinct != "" {
		return AuditNotCovered, acc.distinct
	}
	mr, mg := req.mask(t), got.mask(t)
	if req.namedSyscalls && req.perm != "" && req.list == "exit" && explicitNames(req.syscalls) {
		// An explicit list with a perm filter asks for those syscalls. auditctl
		// loads more (the class list too) and netlink loads the list as
		// written; either covers the list, so coverage asks for the list only.
		mr = auditMask{kind: maskSet, set: map[string]bool{}}
		for _, sc := range req.syscalls {
			mr.set[sc] = true
		}
	}
	cover := AuditCovered
	why := "covered"
	switch {
	case mg.kind == maskAll && req.action == "always":
	case mr.kind == maskSet && mg.kind == maskSet:
		if req.action == "always" {
			for sc := range mr.set {
				if !mg.set[sc] {
					cover, why = AuditNotCovered, "the loaded rule lacks syscall "+sc
					break
				}
			}
		} else if !sameStringSet(mr.set, mg.set) {
			cover, why = AuditNotCovered, "a never rule needs the same syscalls"
		}
	case mr.kind == maskAll && mg.kind == maskSet:
		cover, why = AuditNotCovered, "the requirement covers every syscall, the loaded rule does not"
	case mr.kind == maskAll && mg.kind == maskAll:
	case mr.kind == maskNone && mg.kind == maskNone && mr.spell == mg.spell:
	default:
		cover, why = AuditCoverAmbiguous, "the requirement's loaded syscall list is not known for this machine and audit version"
	}
	if cover == AuditNotCovered {
		return cover, why
	}
	if len(acc.unresolved) > 0 {
		return AuditCoverAmbiguous, strings.Join(acc.unresolved, "; ")
	}
	return cover, why
}

func sortedInts(set map[int64]bool) []int64 {
	out := make([]int64, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// explicitNames reports a syscall list of names only, without "all" or a
// number.
func explicitNames(scs []string) bool {
	for _, sc := range scs {
		if sc == "all" || auditDecimalRe.MatchString(sc) {
			return false
		}
	}
	return len(scs) > 0
}
