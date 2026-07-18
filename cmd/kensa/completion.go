package main

import (
	"fmt"
	"io"
	"strings"
)

// completionSpec describes one subcommand for shell-completion generation: its
// name, a one-line summary, and its long flag names (without the leading --).
//
// This table is the single source of truth for `kensa completion`. It is kept
// honest by the drift-guard in completion_test.go, which runs each command's
// `--help` and fails the build if a flag here diverges from the real flag set —
// so adding a flag to a command without updating this table cannot ship.
type completionSpec struct {
	name    string
	summary string
	flags   []string
}

// globalFlags are accepted before the subcommand (e.g. `kensa --db x check`).
var globalFlags = []string{"db", "help", "version"}

// completionSpecs is the authoritative command/flag table. Order is the order
// commands are offered in completion (mirrors the help grouping loosely).
var completionSpecs = []completionSpec{
	{"detect", "Probe a host and print its capability set", []string{"capability", "format", "help", "host", "key", "no-strict-host-keys", "output", "password", "port", "quiet", "strict-host-keys", "sudo", "sudo-password", "user"}},
	{"check", "Run read-only compliance checks (no apply)", []string{"capability", "category", "config-dir", "control", "format", "framework", "help", "host", "inventory", "key", "limit", "no-strict-host-keys", "output", "password", "port", "quiet", "rule", "rules-dir", "severity", "store", "strict-host-keys", "sudo", "sudo-password", "tag", "user", "var", "verbose", "workers"}},
	{"remediate", "Apply failing rules to a host", []string{"allow-conflicts", "capability", "category", "config-dir", "control", "format", "framework", "help", "host", "key", "no-strict-host-keys", "oscal", "output", "password", "port", "quiet", "rule", "rules-dir", "severity", "strict-host-keys", "sudo", "sudo-password", "tag", "user", "var"}},
	{"rollback", "Roll back a past session or a single transaction by ID", []string{"detail", "format", "help", "host", "info", "key", "list", "no-strict-host-keys", "port", "quiet", "start", "strict-host-keys", "sudo", "sudo-password", "txn", "user"}},
	{"recover", "Compensate transactions interrupted before a terminal status", []string{"db", "host", "key", "port", "quiet", "strict-host-keys", "sudo", "sudo-password", "user"}},
	{"history", "Query the transaction log", []string{"aggregate", "force", "format", "help", "host", "limit", "prune", "quiet", "rule", "since", "stats", "txn"}},
	{"plan", "Preview a rule transaction without executing", []string{"format", "help", "host", "key", "no-strict-host-keys", "password", "port", "quiet", "strict-host-keys", "sudo", "sudo-password", "user"}},
	{"mechanisms", "List registered handler mechanisms", []string{"help"}},
	{"coverage", "Report framework coverage over the corpus", []string{"framework", "help", "rules-dir"}},
	{"list", "Introspection commands (frameworks, sessions, ...)", []string{"help", "rules-dir"}},
	{"info", "Rule/control lookup over the corpus", []string{"cis", "control", "format", "help", "limit", "list-controls", "nist", "quiet", "rhel", "rule", "rules-dir", "stig"}},
	{"diff", "Compare two stored sessions and emit per-rule drift", []string{"format", "help", "quiet", "show-unchanged"}},
	{"agent", "Run kensa as a stdio agent on the target host", []string{"help", "stdio"}},
	{"verify", "Validate the Ed25519 signature on an evidence envelope", []string{"format", "help", "quiet", "trust-dir"}},
	{"migrate", "Apply pending schema migrations and backfill sessions", []string{"db", "help", "quiet"}},
	{"version", "Print version and exit", []string{"help", "version"}},
	{"completion", "Emit a shell completion script (bash|zsh|fish)", []string{"help"}},
}

// supportedShells is the set `kensa completion` can emit, in help order.
var supportedShells = []string{"bash", "zsh", "fish"}

// runCompletion implements `kensa completion [bash|zsh|fish]`. It writes the
// script to stdout and returns a UsageError (exit 2) on a bad invocation, to
// match the CLI's error-to-exit-code contract.
func runCompletion(stdout io.Writer, args []string) error {
	shell := ""
	for _, a := range args {
		switch {
		case a == "-h" || a == "--help":
			printCompletionHelp(stdout)
			return nil
		case strings.HasPrefix(a, "-"):
			return NewUsageError(fmt.Sprintf("unknown flag %q", a))
		case shell != "":
			return NewUsageError(fmt.Sprintf("unexpected argument %q", a))
		default:
			shell = a
		}
	}
	switch shell {
	case "":
		return NewUsageError("specify a shell: bash, zsh, or fish (e.g. 'kensa completion bash')")
	case "bash":
		fmt.Fprint(stdout, bashCompletion())
	case "zsh":
		fmt.Fprint(stdout, zshCompletion())
	case "fish":
		fmt.Fprint(stdout, fishCompletion())
	default:
		return NewUsageError(fmt.Sprintf("unsupported shell %q (want bash, zsh, or fish)", shell))
	}
	return nil
}

func printCompletionHelp(w io.Writer) {
	fmt.Fprint(w, `kensa completion — emit a shell completion script

Usage:
  kensa completion <bash|zsh|fish>

Load it for the current shell session:
  bash:  source <(kensa completion bash)
  zsh:   source <(kensa completion zsh)
  fish:  kensa completion fish | source

Install it permanently:
  bash:  kensa completion bash > /etc/bash_completion.d/kensa
  zsh:   kensa completion zsh  > "${fpath[1]}/_kensa"
  fish:  kensa completion fish > ~/.config/fish/completions/kensa.fish

Completes: subcommands and each subcommand's long flags.
`)
}

// commandNames returns the completable subcommand names in table order.
func commandNames() []string {
	out := make([]string, 0, len(completionSpecs))
	for _, s := range completionSpecs {
		out = append(out, s.name)
	}
	return out
}

// dashFlags prefixes each flag name with "--".
func dashFlags(flags []string) []string {
	out := make([]string, 0, len(flags))
	for _, f := range flags {
		out = append(out, "--"+f)
	}
	return out
}

// bashCompletion returns a self-contained bash completion script (no
// bash-completion package dependency).
func bashCompletion() string {
	var b strings.Builder
	b.WriteString("# bash completion for kensa — generated by `kensa completion bash`\n")
	b.WriteString("_kensa() {\n")
	b.WriteString("    local cur cmd i\n")
	b.WriteString("    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n")
	b.WriteString("    cmd=\"\"\n")
	b.WriteString("    for (( i=1; i < COMP_CWORD; i++ )); do\n")
	b.WriteString("        case \"${COMP_WORDS[i]}\" in\n")
	b.WriteString("            -*) ;;\n")
	b.WriteString("            *) cmd=\"${COMP_WORDS[i]}\"; break ;;\n")
	b.WriteString("        esac\n")
	b.WriteString("    done\n")
	b.WriteString("    if [ -z \"$cmd\" ]; then\n")
	fmt.Fprintf(&b, "        COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n",
		strings.Join(append(commandNames(), dashFlags(globalFlags)...), " "))
	b.WriteString("        return\n")
	b.WriteString("    fi\n")
	b.WriteString("    case \"$cmd\" in\n")
	for _, s := range completionSpecs {
		fmt.Fprintf(&b, "        %s) COMPREPLY=( $(compgen -W %q -- \"$cur\") ) ;;\n",
			s.name, strings.Join(dashFlags(s.flags), " "))
	}
	b.WriteString("    esac\n")
	b.WriteString("}\n")
	b.WriteString("complete -F _kensa kensa\n")
	return b.String()
}

// zshCompletion returns a zsh completion script with command descriptions.
func zshCompletion() string {
	var b strings.Builder
	b.WriteString("#compdef kensa\n")
	b.WriteString("# zsh completion for kensa — generated by `kensa completion zsh`\n")
	b.WriteString("_kensa() {\n")
	b.WriteString("    local -a _kensa_cmds\n")
	b.WriteString("    _kensa_cmds=(\n")
	for _, s := range completionSpecs {
		fmt.Fprintf(&b, "        %q\n", s.name+":"+s.summary)
	}
	b.WriteString("    )\n")
	b.WriteString("    if (( CURRENT == 2 )); then\n")
	b.WriteString("        _describe -t commands 'kensa command' _kensa_cmds\n")
	b.WriteString("        return\n")
	b.WriteString("    fi\n")
	b.WriteString("    case \"${words[2]}\" in\n")
	for _, s := range completionSpecs {
		fmt.Fprintf(&b, "        %s) compadd -- %s ;;\n", s.name, strings.Join(dashFlags(s.flags), " "))
	}
	b.WriteString("    esac\n")
	b.WriteString("}\n")
	b.WriteString("_kensa \"$@\"\n")
	return b.String()
}

// fishCompletion returns a fish completion script.
func fishCompletion() string {
	var b strings.Builder
	b.WriteString("# fish completion for kensa — generated by `kensa completion fish`\n")
	for _, s := range completionSpecs {
		fmt.Fprintf(&b, "complete -c kensa -n __fish_use_subcommand -a %s -d %q\n", s.name, s.summary)
	}
	for _, s := range completionSpecs {
		for _, f := range s.flags {
			fmt.Fprintf(&b, "complete -c kensa -n '__fish_seen_subcommand_from %s' -l %s\n", s.name, f)
		}
	}
	return b.String()
}
