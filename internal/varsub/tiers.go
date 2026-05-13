package varsub

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Phase 3.6 multi-tier variable resolution. Adds per-host /
// per-group / conf.d loaders on top of the Phase 3.5 minimum
// (CLI + defaults). The resolution priority, highest first,
// matches Python kensa's 5-tier scheme:
//
//   1. CLI --var KEY=VALUE                              (operator override)
//   2. <config-dir>/hosts/<hostname>.yml                (per-host)
//   3. <config-dir>/groups/<group>.yml                  (per-group; later wins on collision)
//   4. <config-dir>/conf.d/*.yml (alphabetical)         (conf.d overlay; later wins)
//   5. <config-dir>/defaults.yml                        (corpus-wide defaults)
//
// Use ResolveTiers to compute the merged Variables map for a
// (host, groups, cliOverrides) tuple.

// LoadHost reads <configDir>/hosts/<hostname>.yml and returns
// its `variables:` block. Returns (nil, nil) for empty
// configDir, missing hosts/, or missing per-host file. Same
// scalar-only stringify rules as LoadDefaults.
//
// Hostname is treated as an exact filename: a host listed in
// the inventory as `192.168.1.211` looks for
// hosts/192.168.1.211.yml. No glob expansion.
func LoadHost(configDir, hostname string) (Variables, error) {
	if configDir == "" || hostname == "" {
		return nil, nil
	}
	path := filepath.Join(configDir, "hosts", hostname+".yml")
	return loadVariablesFile(path)
}

// LoadGroups reads <configDir>/groups/<group>.yml for each
// group in groups, in the order given, and merges the
// resulting Variables. Later groups in the slice override
// earlier ones on key collision (matches the inventory
// ordering produced by parseInventory).
//
// Empty configDir or empty groups returns (nil, nil). A
// missing per-group file is silently skipped (operators may
// have defined some groups in the inventory without giving
// every one a config file). Only a present-but-malformed
// file produces an error.
func LoadGroups(configDir string, groups []string) (Variables, error) {
	if configDir == "" || len(groups) == 0 {
		return nil, nil
	}
	merged := Variables{}
	for _, g := range groups {
		path := filepath.Join(configDir, "groups", g+".yml")
		v, err := loadVariablesFile(path)
		if err != nil {
			return nil, err
		}
		if v != nil {
			merged = Merge(merged, v)
		}
	}
	if len(merged) == 0 {
		return nil, nil
	}
	return merged, nil
}

// LoadConfDir reads every <configDir>/conf.d/*.yml, sorted
// alphabetically, and merges the variables in that order.
// Later files override earlier ones on key collision —
// operators name files like 10-base.yml, 50-org.yml,
// 99-local.yml to control precedence.
//
// Empty configDir or missing conf.d/ returns (nil, nil).
// Only a present-but-malformed file produces an error.
func LoadConfDir(configDir string) (Variables, error) {
	if configDir == "" {
		return nil, nil
	}
	dir := filepath.Join(configDir, "conf.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)
	merged := Variables{}
	for _, name := range files {
		v, err := loadVariablesFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if v != nil {
			merged = Merge(merged, v)
		}
	}
	if len(merged) == 0 {
		return nil, nil
	}
	return merged, nil
}

// ResolveTiers computes the effective Variables for a single
// (host, groups, cliOverrides) tuple by merging all six tiers
// in priority order:
//
//	embedded → defaults → conf.d → groups → host → CLI
//
// Each later tier overrides earlier on key collision. The
// embedded tier ships with the kensa-go binary and is the
// lowest-priority floor — operators get sensible defaults out
// of the box for the ~30 templated rules in the production
// corpus. Every other source overrides; operators wanting
// different defaults edit a defaults.yml under --config-dir.
//
// Missing operator tiers (empty configDir, no hosts file, no
// group files, etc.) are silently skipped. Only present-but-
// malformed sources error. The embedded source is validated
// at test time and at process startup; a parse failure here
// would indicate build-time corruption.
//
// The hostname argument may be empty — single-host mode with no per-host
// config dir layer (operators using --host but not having a
// hosts/<host>.yml fall through cleanly).
//
// The groups argument may be empty — single-host mode has no
// groups; only inventory mode populates this.
func ResolveTiers(configDir, hostname string, groups []string, cliOverrides Variables) (Variables, error) {
	embedded, err := BuiltInDefaults()
	if err != nil {
		return nil, err
	}
	defaults, err := LoadDefaults(configDir)
	if err != nil {
		return nil, err
	}
	confd, err := LoadConfDir(configDir)
	if err != nil {
		return nil, err
	}
	groupVars, err := LoadGroups(configDir, groups)
	if err != nil {
		return nil, err
	}
	hostVars, err := LoadHost(configDir, hostname)
	if err != nil {
		return nil, err
	}
	merged := Variables{}
	merged = Merge(merged, embedded)
	merged = Merge(merged, defaults)
	merged = Merge(merged, confd)
	merged = Merge(merged, groupVars)
	merged = Merge(merged, hostVars)
	merged = Merge(merged, cliOverrides)
	if len(merged) == 0 {
		return nil, nil
	}
	return merged, nil
}

// loadVariablesFile reads a YAML file and returns its
// `variables:` block. Centralizes the on-disk shape so
// LoadDefaults / LoadHost / LoadGroups / LoadConfDir share
// validation behavior. Returns (nil, nil) when the file is
// missing.
func loadVariablesFile(path string) (Variables, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc defaultsDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make(Variables, len(doc.Variables))
	for k, v := range doc.Variables {
		if !validVarName(k) {
			return nil, fmt.Errorf("%s: variables.%s: KEY must match [A-Za-z][A-Za-z0-9_]* (rule templates use this vocabulary); the entry is unreachable as written", path, k)
		}
		s, err := stringify(v)
		if err != nil {
			return nil, fmt.Errorf("%s: variables.%s: %w", path, k, err)
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
