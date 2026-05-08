// Command kensa-fuzz is a failure-injection harness for the Kensa
// transaction engine. It deliberately induces a failure at a specific
// transaction phase (capture, apply, or validate), then verifies that
// rollback restores the host to the exact pre-capture state.
//
// Usage:
//
//	kensa-fuzz --host 192.0.2.1 --mechanism sysctl_set --phase apply \
//	    --params '{"key":"kernel.dmesg_restrict","value":"1"}'
//
// Exit codes:
//
//	0  Success: failure injected, rollback ran, fingerprints match.
//	1  Misconfiguration (flag parse error, unknown mechanism).
//	2  Run-time error (connect failure, capture error, engine error).
//	3  Fingerprint mismatch: rollback did not restore pre-state.
//
// The JSON result is always written to stdout. Logs go to stderr.
//
// Integration tests gate on the KENSA_FUZZ_HOST environment variable;
// they are skipped when it is unset.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"

	// Import all handler packages to trigger their init() registrations.
	// Each register.go calls handler.Register(New()), which populates the
	// global registry that the fuzz engine uses to look up handlers.
	_ "github.com/Hanalyx/kensa-go/internal/handlers/auditruleset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/configset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/configsetdropin"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/cronjob"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/fileabsent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/filecontent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/filepermissions"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/kernelmoduledisable"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/mountoptionset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/packageabsent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/packagepresent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/pammoduleconfigure"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/selinuxbooleanset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/servicedisabled"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/serviceenabled"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/servicemasked"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/sysctlset"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handler"
	sshtransport "github.com/Hanalyx/kensa-go/internal/transport/ssh"
)

// config collects CLI flags.
type config struct {
	host      string
	port      int
	user      string
	keyPath   string
	sudo      bool
	mechanism string
	phase     string
	params    api.Params
	timeout   time.Duration
}

// FuzzResult is the JSON-encoded outcome written to stdout.
type FuzzResult struct {
	// Phase is the injected failure phase: "capture", "apply", or "validate".
	Phase string `json:"phase"`
	// Mechanism is the handler name used in the transaction.
	Mechanism string `json:"mechanism"`
	// TransactionStatus is the engine's terminal status string.
	TransactionStatus string `json:"transaction_status"`
	// RollbackRan is true when the engine executed the rollback phase.
	RollbackRan bool `json:"rollback_ran"`
	// FingerprintMatch is true when the post-rollback host state matches
	// the pre-injection capture. This is the core assertion.
	FingerprintMatch bool `json:"fingerprint_match"`
	// PreFingerprint is the PreState.Data captured before the injection run.
	PreFingerprint map[string]interface{} `json:"pre_fingerprint"`
	// PostFingerprint is the PreState.Data captured after rollback completes.
	PostFingerprint map[string]interface{} `json:"post_fingerprint"`
	// Error is set when the harness itself failed (not the injected failure).
	Error string `json:"error,omitempty"`
}

// Short-letter constants for kensa-fuzz. Mirror the kensa CLI
// conventions (per docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md §4):
// -h is help, -H is host, -u user, -p port, -k key, -s sudo. -m for
// --mechanism (no conflict in this binary). --phase, --params,
// --timeout are long-only (run-shape parameters; rare enough to skip
// short letters).
const (
	shortHelp      = "h"
	shortHost      = "H"
	shortUser      = "u"
	shortPort      = "p"
	shortKey       = "k"
	shortSudo      = "s"
	shortMechanism = "m"
)

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

// runCLI parses argv, runs the fuzz harness, and returns the process
// exit code per the documented contract:
//
//	0  Success: failure injected, rollback ran, fingerprints match.
//	1  Misconfiguration (flag parse error, unknown mechanism, missing host).
//	2  Run-time error (connect failure, capture error, engine error).
//	3  Fingerprint mismatch: rollback did not restore pre-state.
//
// Extracted from main for testability — call runCLI directly with
// synthetic argv slices.
func runCLI(argv []string) int {
	// Backward-compat: stdlib flag accepted single-dash long forms
	// (`-host`, `-mechanism`). Rewrite to pflag's `--host` form with
	// a deprecation warning. Removed in v0.2.
	argv = rewriteLegacyLongForm(argv, map[string]bool{
		"host": true, "port": true, "user": true, "key": true,
		"sudo": true, "mechanism": true, "phase": true,
		"params": true, "timeout": true,
	})

	fs := pflag.NewFlagSet("kensa-fuzz", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp   bool
		host       string
		port       int
		user       string
		keyPath    string
		sudo       bool
		mechanism  string
		phase      string
		paramsJSON string
		timeout    time.Duration
	)
	// Default for --host honors the KENSA_FUZZ_HOST env var (existing
	// behavior preserved per C-007 acceptance).
	hostDefault := os.Getenv("KENSA_FUZZ_HOST")

	fs.BoolVarP(&showHelp, "help", shortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", shortHost, hostDefault, "target host (or KENSA_FUZZ_HOST env)")
	fs.IntVarP(&port, "port", shortPort, 22, "SSH port")
	fs.StringVarP(&user, "user", shortUser, "", "SSH user (default: ssh client default)")
	fs.StringVarP(&keyPath, "key", shortKey, "", "SSH identity file (default: ssh-agent / ~/.ssh/config)")
	fs.BoolVarP(&sudo, "sudo", shortSudo, false, "wrap remote commands in sudo -n sh -c")
	fs.StringVarP(&mechanism, "mechanism", shortMechanism, "", "mechanism name, e.g. sysctl_set or file_content")
	fs.StringVar(&phase, "phase", "apply", "phase to inject failure at: capture, apply, or validate (long-only)")
	fs.StringVar(&paramsJSON, "params", "{}", "JSON-encoded mechanism params (long-only)")
	fs.DurationVar(&timeout, "timeout", 60*time.Second, "per-run timeout (long-only)")

	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printUsage(os.Stdout, fs)
			return 0
		}
		fmt.Fprintf(os.Stderr, "kensa-fuzz: %v\n", err)
		fmt.Fprintln(os.Stderr, "Try 'kensa-fuzz --help' for usage.")
		return 1
	}
	if showHelp {
		printUsage(os.Stdout, fs)
		return 0
	}

	if host == "" {
		fmt.Fprintln(os.Stderr, "kensa-fuzz: --host is required (or set KENSA_FUZZ_HOST)")
		return 1
	}
	if mechanism == "" {
		fmt.Fprintln(os.Stderr, "kensa-fuzz: --mechanism is required")
		return 1
	}

	var params api.Params
	if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
		fmt.Fprintf(os.Stderr, "kensa-fuzz: invalid --params JSON: %v\n", err)
		return 1
	}

	cfg := config{
		host:      host,
		port:      port,
		user:      user,
		keyPath:   keyPath,
		sudo:      sudo,
		mechanism: mechanism,
		phase:     phase,
		params:    params,
		timeout:   timeout,
	}

	return run(cfg)
}

// printUsage writes the kensa-fuzz help text. --help → stdout per GNU;
// usage errors → stderr; caller picks.
func printUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa-fuzz [flags]

Failure-injection harness for the Kensa transaction engine. Deliberately
induces a failure at a specific transaction phase (capture, apply, or
validate), then verifies that rollback restores the host to the exact
pre-capture state.

Flags:
%s
Exit codes:
  0  Success: failure injected, rollback ran, fingerprints match.
  1  Misconfiguration (flag parse error, unknown mechanism, missing host).
  2  Run-time error (connect failure, capture error, engine error).
  3  Fingerprint mismatch: rollback did not restore pre-state.

The JSON result is always written to stdout. Logs go to stderr.

Examples:
  kensa-fuzz -H 192.0.2.1 -m sysctl_set --phase apply \
    --params '{"key":"kernel.dmesg_restrict","value":"1"}'

  KENSA_FUZZ_HOST=192.168.1.211 kensa-fuzz -m file_permissions \
    --params '{"path":"/etc/ssh/sshd_config","mode":"0600"}' \
    --phase validate
`, fs.FlagUsages())
}

// rewriteLegacyLongForm converts stdlib-flag-style single-dash long
// forms (`-host foo`, `-mechanism sysctl_set`) to pflag's double-dash
// form. Mirrors the helpers in cmd/kensa and cmd/kensa-validate;
// scoped to this binary. Removed in v0.2.
func rewriteLegacyLongForm(argv []string, longNames map[string]bool) []string {
	out := make([]string, 0, len(argv))
	warned := false
	for _, a := range argv {
		if !strings.HasPrefix(a, "-") || strings.HasPrefix(a, "--") {
			out = append(out, a)
			continue
		}
		name := a[1:]
		if eq := strings.Index(name, "="); eq != -1 {
			name = name[:eq]
		}
		if len(name) > 1 && longNames[name] {
			if !warned {
				fmt.Fprintln(os.Stderr, "kensa-fuzz: warning: stdlib-style single-dash long flags are deprecated; use --"+name+" (will be removed in v0.2)")
				warned = true
			}
			out = append(out, "-"+a)
			continue
		}
		out = append(out, a)
	}
	return out
}

// run executes the fuzz scenario and returns the process exit code.
// Splitting os.Exit from the deferred cancel avoids the exitAfterDefer warning.
func run(cfg config) int {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	result, err := runFuzz(ctx, cfg)
	if err != nil {
		writeResult(&FuzzResult{
			Phase:     cfg.phase,
			Mechanism: cfg.mechanism,
			Error:     err.Error(),
		})
		return 2
	}

	writeResult(result)
	if !result.FingerprintMatch {
		return 3
	}
	return 0
}

// writeResult JSON-encodes r to stdout with two-space indentation.
func writeResult(r *FuzzResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

// failingHandler wraps a real CombinedHandler and injects an error at
// a specific phase ("capture" or "apply"). The rollback path always
// delegates to the real handler so the engine can restore pre-state
// after apply-phase injection.
//
// For validate-phase injection use engine.WithForceValidateFail with
// the unwrapped real handler — no wrapper needed.
type failingHandler struct {
	real  api.CombinedHandler
	phase string // "capture" or "apply"
}

func (f *failingHandler) Name() string     { return f.real.Name() }
func (f *failingHandler) Capturable() bool { return true }

func (f *failingHandler) Capture(ctx context.Context, t api.Transport, params api.Params) (*api.PreState, error) {
	if f.phase == "capture" {
		return nil, errors.New("kensa-fuzz: injected capture failure")
	}
	return f.real.Capture(ctx, t, params)
}

func (f *failingHandler) Apply(ctx context.Context, t api.Transport, params api.Params, pre *api.PreState) (*api.StepResult, error) {
	if f.phase == "apply" {
		return nil, errors.New("kensa-fuzz: injected apply failure")
	}
	return f.real.Apply(ctx, t, params, pre)
}

func (f *failingHandler) Rollback(ctx context.Context, t api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	return f.real.Rollback(ctx, t, pre)
}

// runFuzz is the testable core: connects to the host, injects the
// failure, runs the transaction, re-captures, and compares fingerprints.
func runFuzz(ctx context.Context, cfg config) (*FuzzResult, error) {
	// Validate phase argument early.
	switch cfg.phase {
	case "capture", "apply", "validate":
	default:
		return nil, fmt.Errorf("unknown phase %q: must be capture, apply, or validate", cfg.phase)
	}

	// Look up the real handler from the globally-populated registry.
	h, ok := handler.Default().Get(cfg.mechanism)
	if !ok {
		return nil, fmt.Errorf("mechanism %q is not registered; is its handler package imported?", cfg.mechanism)
	}
	combined, ok := h.(api.CombinedHandler)
	if !ok {
		return nil, fmt.Errorf("mechanism %q is not capturable; fuzz rollback verification requires a capturable mechanism", cfg.mechanism)
	}

	// Connect to the target host.
	transport, err := sshtransport.Connect(ctx, sshtransport.Config{
		Host:    cfg.host,
		Port:    cfg.port,
		User:    cfg.user,
		KeyPath: cfg.keyPath,
		Sudo:    cfg.sudo,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer transport.Close()

	// Pre-fingerprint: capture the current host state before the injection
	// run. This is the expected state after rollback completes.
	preState, err := combined.Capture(ctx, transport, cfg.params)
	if err != nil {
		return nil, fmt.Errorf("pre-fingerprint capture: %w", err)
	}

	// Build a custom registry containing only the (possibly wrapped)
	// handler so the engine does not accidentally invoke other handlers.
	reg := handler.NewRegistry()
	engineOpts := []engine.Option{engine.WithRegistry(reg)}

	switch cfg.phase {
	case "capture", "apply":
		// Wrap the real handler; failure is injected at the specified phase.
		reg.Register(&failingHandler{real: combined, phase: cfg.phase})
	case "validate":
		// Real handler runs normally. The engine's validate phase is forced
		// to fail via WithForceValidateFail, triggering inline rollback.
		reg.Register(combined)
		engineOpts = append(engineOpts, engine.WithForceValidateFail())
	}

	eng := engine.New(engineOpts...)

	txn := &api.Transaction{
		RuleID:        "kensa-fuzz",
		HostID:        cfg.host,
		Transactional: true,
		Steps: []api.Step{
			{Index: 0, Mechanism: cfg.mechanism, Params: cfg.params},
		},
	}

	txnResult, err := eng.Run(ctx, transport, txn, false)
	if err != nil {
		return nil, fmt.Errorf("engine.Run: %w", err)
	}

	// Post-fingerprint: capture the host state after the injection run
	// and any rollback. For capture-phase injection no apply ran so the
	// host is trivially unchanged; the comparison still confirms the
	// capture itself is stable.
	postState, err := combined.Capture(ctx, transport, cfg.params)
	if err != nil {
		return nil, fmt.Errorf("post-fingerprint capture: %w", err)
	}

	rollbackRan := txnResult.Status == api.StatusRolledBack

	return &FuzzResult{
		Phase:             cfg.phase,
		Mechanism:         cfg.mechanism,
		TransactionStatus: string(txnResult.Status),
		RollbackRan:       rollbackRan,
		FingerprintMatch:  fingerprintsMatch(preState, postState),
		PreFingerprint:    preState.Data,
		PostFingerprint:   postState.Data,
	}, nil
}

// fingerprintsMatch returns true when pre and post have byte-identical
// JSON representations of their Data maps. The JSON round-trip
// normalises map key order so the comparison is order-independent.
func fingerprintsMatch(pre, post *api.PreState) bool {
	if pre == nil && post == nil {
		return true
	}
	if pre == nil || post == nil {
		return false
	}
	a, errA := json.Marshal(pre.Data)
	b, errB := json.Marshal(post.Data)
	if errA != nil || errB != nil {
		return false
	}
	return string(a) == string(b)
}
