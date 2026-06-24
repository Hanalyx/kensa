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
	Kind  string // package | sysctl | path | service | module
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
	}
	return "", ""
}
