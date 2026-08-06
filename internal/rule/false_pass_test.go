package rule

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A check that can report compliance without verifying it is the defect class
// this corpus has shipped four times: gdm-graphical-banner passing on a host with
// no graphical stack, shell-timeout-600 passing a host at double its limit,
// nftables-default-deny passing on "firewalld is running", and journald-to-rsyslog
// passing unconditionally. Each was found by hand, months apart. These two checks
// are the mechanical half of that search, run on every commit.
//
// @spec catalog-coverage-crosswalk
// @ac AC-12

// alwaysPassAllowed are checks that deliberately surface information for a human
// and then exit 0, because a check has no verdict for "ran, needs disposition".
// The list may shrink; adding to it needs a reason written here, because every
// entry is a rule that reports compliant regardless of host state.
//
// auditd-log-storage-week is NOT here. It has a real failure path, so this test
// does not see it, yet a partition under the guideline prints MANUAL REVIEW and
// exits 0. That variant needs observed fleet data to spot and is caught by the
// class D sweep instead, not by any unit test.
var alwaysPassAllowed = map[string]string{
	"firewall-ppsm-cal":                 "surfaces firewall config for PPSM review",
	"firewall-remote-access-ppsm":       "same, remote-access rules",
	"firewalld-services-ports-reviewed": "prints allowed services and ports for review",
	"ipsec-tunnels-authorized":          "surfaces configured tunnels",
	"no-unauthorized-accounts":          "lists local accounts for an ISSO to compare",
	"pki-certificate-validation":        "reports whether an SSSD PKI CA database exists",
	"temporary-account-expiry":          "lists accounts with no expiry",
}

type fpDoc struct {
	ID              string `yaml:"id"`
	Implementations []struct {
		When    interface{}            `yaml:"when"`
		Default bool                   `yaml:"default"`
		Check   map[string]interface{} `yaml:"check"`
	} `yaml:"implementations"`
}

func walkRules(t *testing.T, fn func(fpDoc)) {
	t.Helper()
	root := filepath.Join("..", "..", "rules")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".yml" {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var d fpDoc
		if yaml.Unmarshal(b, &d) != nil || d.ID == "" {
			return nil
		}
		fn(d)
		return nil
	})
	if err != nil {
		t.Fatalf("walk rules: %v", err)
	}
}

var exitRe = regexp.MustCompile(`\bexit\s+(\d+)`)

// alwaysPasses reports whether a command check can only ever exit 0. The final
// COMMAND is what matters, not the final line: "echo ...; exit 0" ends on a line
// starting with echo, which hid journald-to-rsyslog from an earlier version.
func alwaysPasses(run string) bool {
	joined := strings.ReplaceAll(run, "\\\n", " ")
	exits := exitRe.FindAllStringSubmatch(joined, -1)
	if len(exits) == 0 {
		return false
	}
	for _, m := range exits {
		if m[1] != "0" {
			return false
		}
	}
	var body []string
	for _, l := range strings.Split(strings.TrimSpace(joined), "\n") {
		if s := strings.TrimSpace(l); s != "" {
			body = append(body, s)
		}
	}
	if len(body) == 0 {
		return false
	}
	parts := strings.Split(body[len(body)-1], ";")
	return strings.HasPrefix(strings.TrimSpace(parts[len(parts)-1]), "exit 0")
}

func TestNoNewAlwaysPassingChecks(t *testing.T) {
	t.Log("// @spec catalog-coverage-crosswalk")
	t.Log("// @ac AC-12")
	var found []string
	walkRules(t, func(d fpDoc) {
		for _, i := range d.Implementations {
			run, _ := i.Check["run"].(string)
			if run != "" && alwaysPasses(run) {
				found = append(found, d.ID)
				return
			}
		}
	})
	sort.Strings(found)
	for _, id := range found {
		if _, ok := alwaysPassAllowed[id]; !ok {
			t.Errorf("rule %q has a check that can only exit 0, so it reports compliant "+
				"regardless of host state. Give it a real failure path, gate it on a "+
				"capability so it skips, or add it to alwaysPassAllowed with a reason.", id)
		}
	}
	for id := range alwaysPassAllowed {
		if !fpContains(found, id) {
			t.Errorf("rule %q is in alwaysPassAllowed but no longer always passes; "+
				"remove the entry so the list stays honest", id)
		}
	}
	t.Logf("%d always-passing checks, all accounted for", len(found))
}

// TestNoDivergentDefault catches a default implementation that checks something
// unrelated to the capability-gated one it stands in for. nftables-default-deny
// gated the real ruleset check on a capability that was never probed, so every
// host fell through to a default that only asked whether firewalld was running,
// and it passed on a host whose nft policy was accept.
func TestNoDivergentDefault(t *testing.T) {
	t.Log("// @spec catalog-coverage-crosswalk")
	t.Log("// @ac AC-12")
	noise := map[string]bool{"if": true, "then": true, "else": true, "fi": true,
		"for": true, "do": true, "done": true, "case": true, "esac": true,
		"echo": true, "exit": true, "printf": true, "test": true, "true": true,
		"false": true, "set": true, "local": true, "return": true, "grep": true,
		"awk": true, "sed": true, "cut": true, "tr": true, "head": true,
		"tail": true, "sort": true, "uniq": true, "wc": true, "xargs": true,
		"cat": true, "read": true, "while": true, "eval": true, "command": true}
	pathRe := regexp.MustCompile(`/(?:etc|proc|sys|var|usr)/[A-Za-z0-9._/-]+`)
	unitRe := regexp.MustCompile(`\b(?:is-active|is-enabled)\s+([A-Za-z0-9._-]+)`)
	cmdRe := regexp.MustCompile(`(?:^|[;&|]|\\n)\s*([a-z][a-z0-9._-]{1,20})\b`)
	subjects := func(c map[string]interface{}) map[string]bool {
		b, _ := json.Marshal(c)
		s := string(b)
		out := map[string]bool{}
		for _, m := range pathRe.FindAllString(s, -1) {
			out[m] = true
		}
		for _, m := range unitRe.FindAllStringSubmatch(s, -1) {
			out[m[1]] = true
		}
		for _, m := range cmdRe.FindAllStringSubmatch(s, -1) {
			if !noise[m[1]] {
				out[m[1]] = true
			}
		}
		return out
	}
	walkRules(t, func(d fpDoc) {
		gated, dflt := map[string]bool{}, map[string]bool{}
		for _, i := range d.Implementations {
			target := dflt
			if i.When != nil {
				target = gated
			} else if !i.Default {
				continue
			}
			for k := range subjects(i.Check) {
				target[k] = true
			}
		}
		if len(gated) == 0 || len(dflt) == 0 {
			return
		}
		for k := range gated {
			if dflt[k] {
				return // they overlap; the default stands in for the same thing
			}
		}
		t.Errorf("rule %q: its default implementation inspects %v while the gated one "+
			"inspects %v. A default that answers a different question than the gate it "+
			"replaces reports on the wrong subject when the capability is absent.",
			d.ID, fpKeys(dflt), fpKeys(gated))
	})
}

func fpContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func fpKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}
