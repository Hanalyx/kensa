package main

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

// flagGroup is a labeled set of flag names rendered as one
// section in --help output.
type flagGroup struct {
	title string
	flags []string
}

// formatGroupedUsages renders fs's flags grouped by `groups`. Flags
// not listed in any group are appended under "Other options" so a
// future flag added without updating the group definition still
// appears in --help (drift-resistant).
//
// The categorization is purely a presentation concern; parsing
// continues against the single fs the caller built. We construct
// per-group sub-FlagSets only to drive pflag's FlagUsages() table
// formatter.
func formatGroupedUsages(fs *pflag.FlagSet, groups []flagGroup) string {
	var b strings.Builder
	seen := make(map[string]bool)

	for _, g := range groups {
		sub := pflag.NewFlagSet(g.title, pflag.ContinueOnError)
		sub.SortFlags = false
		anyFlag := false
		for _, name := range g.flags {
			f := fs.Lookup(name)
			if f == nil {
				continue
			}
			sub.AddFlag(f)
			seen[name] = true
			anyFlag = true
		}
		if !anyFlag {
			continue
		}
		fmt.Fprintf(&b, "%s:\n%s\n", g.title, sub.FlagUsages())
	}

	// Catch-all for flags we didn't categorize. Help text for
	// --help itself goes under General.
	other := pflag.NewFlagSet("other", pflag.ContinueOnError)
	other.SortFlags = false
	general := pflag.NewFlagSet("general", pflag.ContinueOnError)
	general.SortFlags = false
	fs.VisitAll(func(f *pflag.Flag) {
		if seen[f.Name] {
			return
		}
		if f.Name == "help" {
			general.AddFlag(f)
		} else {
			other.AddFlag(f)
		}
	})
	if hasAnyFlag(other) {
		fmt.Fprintf(&b, "Other options:\n%s\n", other.FlagUsages())
	}
	if hasAnyFlag(general) {
		fmt.Fprintf(&b, "General:\n%s\n", general.FlagUsages())
	}

	return strings.TrimRight(b.String(), "\n")
}

// hasAnyFlag returns true when fs has at least one flag visible
// to FlagUsages. The pflag package exports no Len(), so we
// VisitAll once.
func hasAnyFlag(fs *pflag.FlagSet) bool {
	any := false
	fs.VisitAll(func(*pflag.Flag) { any = true })
	return any
}

// detectFlagGroups defines the --help layout for `kensa detect`.
// Per docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md §3.2, detect
// uses target_options + a small subset of output_options. There
// is intentionally no Rule options group here — detect doesn't
// load rules; future contributors must NOT add --severity / --tag
// / --rules-dir on detect "for symmetry".
var detectFlagGroups = []flagGroup{
	{
		title: "Target options",
		flags: []string{
			"host", "user", "key", "password",
			"port", "sudo",
			"strict-host-keys", "no-strict-host-keys",
			"capability",
		},
	},
	{
		title: "Output options",
		flags: []string{"format", "output", "quiet"},
	},
}

// checkFlagGroups defines the --help layout for `kensa check`:
// target_options + rule_options + output_options + the
// subcommand-specific --verbose flag.
var checkFlagGroups = []flagGroup{
	{
		title: "Target options",
		flags: []string{
			"host", "user", "key", "password",
			"port", "sudo",
			"strict-host-keys", "no-strict-host-keys",
			"capability",
			"inventory", "limit", "workers",
		},
	},
	{
		title: "Rule options",
		flags: []string{
			"rules-dir", "rule",
			"severity", "tag", "category",
			"framework", "control",
			"var", "config-dir",
		},
	},
	{
		title: "Output options",
		flags: []string{"format", "output", "quiet", "verbose"},
	},
}

// infoFlagGroups defines the --help layout for `kensa info`
// (C-047). Mode flags first (the operator must pick one),
// then Filters (compose with the chosen mode), then Output.
// `--rules-dir` is in Mode because it's required regardless
// of which mode the operator picks — surfacing it under
// Output would imply it's an output knob.
var infoFlagGroups = []flagGroup{
	{
		title: "Mode (pick one)",
		flags: []string{"rule", "control", "list-controls", "rules-dir"},
	},
	{
		title: "Filter options",
		flags: []string{"cis", "stig", "nist", "rhel"},
	},
	{
		title: "Output options",
		flags: []string{"format", "limit", "quiet"},
	},
}

// rollbackFlagGroups defines the --help layout for `kensa
// rollback` (C-049). Mode flags first; Target options gate
// only the executing modes (--start / --txn); Output applies
// to all modes.
var rollbackFlagGroups = []flagGroup{
	{
		title: "Mode (pick one)",
		flags: []string{"list", "info", "start", "txn", "detail"},
	},
	{
		title: "Target options (required for --start and --txn)",
		flags: []string{
			"host", "user", "key",
			"port", "sudo",
			"strict-host-keys", "no-strict-host-keys",
		},
	},
	{
		title: "Output options",
		flags: []string{"format", "quiet"},
	},
}

// remediateFlagGroups defines the --help layout for `kensa
// remediate`. Same shape as check minus inventory/limit/workers
// (remediate is single-host today) plus the deprecated --oscal.
var remediateFlagGroups = []flagGroup{
	{
		title: "Target options",
		flags: []string{
			"host", "user", "key", "password",
			"port", "sudo",
			"strict-host-keys", "no-strict-host-keys",
			"capability",
		},
	},
	{
		title: "Rule options",
		flags: []string{
			"rules-dir", "rule",
			"severity", "tag", "category",
			"framework", "control",
			"var", "config-dir",
		},
	},
	{
		title: "Output options",
		flags: []string{"format", "output", "oscal", "quiet"},
	},
}
