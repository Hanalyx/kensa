package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every remediation mechanism the corpus uses must be classified in
// controlChannelMechanisms, whether or not it is risky.
//
// The defect this prevents was not a wrong judgment. Six mechanisms across 124
// rules were absent from the map ENTIRELY, and a missing key reads as false, so
// each was silently treated as safe. One of them, crypto_policy_set, was then
// measured severing SSH on a live container: switching a host to FIPS
// regenerates sshd's accepted key algorithms without ed25519, which locks out
// any operator using a modern default key. No deadman timer was armed, and the
// mechanism is non-capturable, so there was no way back.
//
// The map's own comment says false negatives risk atomicity violations while
// false positives only cost extra scheduling. A list that has to be REMEMBERED
// cannot honor that. This makes forgetting it a build failure.
func TestEveryCorpusMechanismIsClassified(t *testing.T) {
	root := filepath.Join("..", "..", "rules")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("rule corpus not present: %v", err)
	}

	type ruleDoc struct {
		ID              string `yaml:"id"`
		Implementations []struct {
			Remediation struct {
				Mechanism string `yaml:"mechanism"`
				Steps     []struct {
					Mechanism string `yaml:"mechanism"`
				} `yaml:"steps"`
			} `yaml:"remediation"`
		} `yaml:"implementations"`
	}

	used := map[string]string{} // mechanism -> first rule that uses it
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".yml") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var d ruleDoc
		if yaml.Unmarshal(raw, &d) != nil || d.ID == "" {
			return nil
		}
		for _, impl := range d.Implementations {
			r := impl.Remediation
			all := []string{r.Mechanism}
			for _, s := range r.Steps {
				all = append(all, s.Mechanism)
			}
			for _, m := range all {
				if m != "" {
					if _, seen := used[m]; !seen {
						used[m] = d.ID
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk corpus: %v", err)
	}
	if len(used) == 0 {
		t.Fatal("no mechanisms found; the walk is broken, not the corpus")
	}

	var missing []string
	for m, rule := range used {
		if _, classified := controlChannelMechanisms[m]; !classified {
			missing = append(missing, m+" (e.g. "+rule+")")
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d mechanism(s) used by the corpus are not classified in "+
			"controlChannelMechanisms, so they are silently treated as unable to cut "+
			"the SSH control channel and arm no deadman timer:\n  %s\n"+
			"Add each one. If it cannot sever the channel say so with false and a "+
			"reason; if it can, or you are unsure, say true. The map's stated bias is "+
			"that a false positive costs only a timer while a false negative can cost "+
			"the host.", len(missing), strings.Join(missing, "\n  "))
	}
	t.Logf("%d mechanisms in the corpus, all classified", len(used))
}
