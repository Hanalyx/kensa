package catalog

import (
	"regexp"
	"strings"
)

// Target is a structured subject extracted from a control's check/fix commands or
// from a rule's check method: a (kind, value) pair like (package, telnetd) or
// (sysctl, kernel.dmesg_restrict). Matching controls to rules on Targets — the
// argument to a command, not words in prose — is what makes the crosswalk precise.
type Target struct {
	Kind  string // package | sysctl | path | service | module | config
	Value string
}

// Command-anchored extractors: each captures the ARGUMENT of a real command, so a
// STIG control's subject is the package dpkg queries / the param sysctl sets / the
// path stat checks — never an English word in the surrounding prose. This is the
// fix for the false positives that naive substring matching produced (e.g. "sudo"
// matching every check, "can" matching the word in a sentence).
var (
	pkgRE = []*regexp.Regexp{
		regexp.MustCompile(`dpkg\s+-l\s*\|\s*grep\s+(?:-\w+\s+)?"?([a-z0-9][a-z0-9.+-]{2,})"?`),
		regexp.MustCompile(`apt(?:-get)?\s+(?:install|remove|purge)\s+(?:-y\s+)?"?([a-z0-9][a-z0-9.+-]{2,})"?`),
		regexp.MustCompile(`(?:rpm\s+-q|dnf\s+(?:install|remove)|yum\s+(?:install|remove))\s+"?([a-z0-9][a-z0-9.+-]{2,})"?`),
	}
	sysctlRE = []*regexp.Regexp{
		regexp.MustCompile(`sysctl\s+(?:-w\s+)?([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)`),
		regexp.MustCompile(`/proc/sys/([a-z0-9_/]+)`),
	}
	pathRE = []*regexp.Regexp{
		regexp.MustCompile(`(?:stat|chmod|chown|chgrp)\s+(?:-\S+\s+|'[^']*'\s+|"[^"]*"\s+|[0-7]{3,4}\s+|\w+:\w+\s+)*(/[\w./-]+)`),
	}
	svcRE = []*regexp.Regexp{
		regexp.MustCompile(`systemctl\s+(?:is-enabled|is-active|status|enable|disable|mask|unmask|start|stop|reload)\s+"?([\w.@-]+)`),
	}
	modRE = []*regexp.Regexp{
		regexp.MustCompile(`modprobe\s+(?:-\w+\s+)*([a-z0-9_-]{2,})`),
		regexp.MustCompile(`install\s+([a-z0-9_-]{2,})\s+/bin/(?:true|false)`),
	}
	// Tokens that are command words or filler, never a real subject.
	targetStop = map[string]bool{
		"sudo": true, "grep": true, "the": true, "not": true, "installed": true,
		"package": true, "following": true, "ii": true, "true": true, "false": true, "y": true,
	}

	// Mount-option extractor: a mount control's subject is a (mount point, option)
	// pair. The STIG check reads "<path>" is mounted with the "<option>" option,
	// so capture both to match per-option mount rules precisely.
	mountRE = regexp.MustCompile(`"(/[\w./-]+)"\s+is\s+mounted\s+with\s+the\s+"(\w+)"\s+option`)

	// Config-directive extractors. A config control's subject is the directive KEY in
	// a config file: "dcredit = -1" (pwquality.conf), "PASS_MAX_DAYS 60" (login.defs),
	// "X11UseLocalhost yes" (sshd_config). These have no command to anchor on, so the
	// extractors are looser than the command ones — that is safe because a control_target
	// that matches no rule_target is simply never joined. The only real risk is a
	// spurious key that collides with a genuine rule config-key, which configStop guards.
	cfgAssignRE       = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9_]{2,})\s*=\s*\S`)                          // key = value
	cfgSSHDirectiveRE = regexp.MustCompile(`\b([A-Z][A-Za-z0-9]*[a-z][A-Za-z0-9]*)\s+(?:yes|no|\d|"|[a-z])`) // CamelCase directive
	cfgLoginDefsRE    = regexp.MustCompile(`\b([A-Z][A-Z0-9_]{2,})\s+\S`)                                    // UPPERCASE_KEY value

	// configStop excludes generic prose tokens that could collide with a real rule
	// config-key. Spurious non-colliding keys are inert, so this need only cover the
	// words that actually appear as config-key-shaped tokens in STIG fix prose.
	configStop = map[string]bool{
		"ubuntu": true, "lts": true, "dod": true, "ssh": true, "add": true, "set": true,
		"edit": true, "the": true, "value": true, "line": true, "file": true, "following": true,
		"configure": true, "modify": true, "ensure": true, "restart": true, "update": true,
		"uncomment": true, "comment": true, "remove": true, "note": true, "default": true,
		"system": true, "server": true, "client": true, "daemon": true, "mac": true, "use": true,
		// "audit" is a real faillock.conf key but is hopelessly generic in STIG prose
		// (grub "audit=1", the audit subsystem, "session audit"), so a control mentioning
		// it almost never means the faillock directive — exclude to avoid the collision.
		"audit": true,
	}
)

// ExtractCommandTargets pulls structured subjects from a control's check/fix text.
// Deduplicated; lowercased (paths excepted). Best-effort and precision-first: a
// command it does not recognize yields nothing rather than a guess.
func ExtractCommandTargets(text string) []Target {
	seen := map[Target]bool{}
	add := func(kind, val string) {
		val = strings.TrimSpace(val)
		if val == "" || targetStop[strings.ToLower(val)] {
			return
		}
		if kind == "config" && configStop[strings.ToLower(val)] {
			return
		}
		t := Target{Kind: kind, Value: val}
		seen[t] = true
	}
	for _, rx := range pkgRE {
		for _, m := range rx.FindAllStringSubmatch(text, -1) {
			add("package", strings.ToLower(m[1]))
		}
	}
	for _, rx := range sysctlRE {
		for _, m := range rx.FindAllStringSubmatch(text, -1) {
			v := m[1]
			if strings.Contains(v, "/") {
				v = strings.ReplaceAll(v, "/", ".")
			}
			add("sysctl", strings.ToLower(v))
		}
	}
	for _, rx := range pathRE {
		for _, m := range rx.FindAllStringSubmatch(text, -1) {
			if len(m[1]) > 4 {
				add("path", m[1])
			}
		}
	}
	for _, rx := range svcRE {
		for _, m := range rx.FindAllStringSubmatch(text, -1) {
			add("service", strings.ToLower(strings.TrimSuffix(m[1], ".service")))
		}
	}
	for _, rx := range modRE {
		for _, m := range rx.FindAllStringSubmatch(text, -1) {
			add("module", strings.ToLower(m[1]))
		}
	}
	// Config directives: key=value everywhere; CamelCase only in an ssh_config/sshd_config
	// context; UPPERCASE_KEY only in a login.defs context — the file mention is the anchor
	// that keeps the looser space-separated forms from firing on arbitrary prose.
	for _, m := range mountRE.FindAllStringSubmatch(text, -1) {
		add("mount", m[1]+":"+strings.ToLower(m[2]))
	}
	for _, m := range cfgAssignRE.FindAllStringSubmatch(text, -1) {
		add("config", strings.ToLower(m[1]))
	}
	if strings.Contains(text, "ssh_config") || strings.Contains(text, "sshd_config") {
		for _, m := range cfgSSHDirectiveRE.FindAllStringSubmatch(text, -1) {
			add("config", strings.ToLower(m[1]))
		}
	}
	if strings.Contains(text, "login.defs") {
		for _, m := range cfgLoginDefsRE.FindAllStringSubmatch(text, -1) {
			add("config", strings.ToLower(m[1]))
		}
	}
	out := make([]Target, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	return out
}

// ruleTarget maps a rule check method + params to its structured Target, or
// ("", "") when the method has no clean subject (e.g. command/manual).
func ruleTarget(method string, params map[string]string) (kind, value string) {
	switch method {
	case "sysctl_value":
		return "sysctl", strings.ToLower(params["key"])
	case "package_state":
		return "package", strings.ToLower(params["name"])
	case "service_state":
		return "service", strings.ToLower(strings.TrimSuffix(params["name"], ".service"))
	case "kernel_module_state":
		return "module", strings.ToLower(params["name"])
	case "file_permission":
		return "path", params["path"]
	case "config_value", "sshd_effective_config":
		return "config", strings.ToLower(params["key"])
	}
	return "", ""
}
