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
	"flag"
	"fmt"
	"os"
	"time"

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

func main() {
	var (
		host       = flag.String("host", os.Getenv("KENSA_FUZZ_HOST"), "target host (or KENSA_FUZZ_HOST env)")
		port       = flag.Int("port", 22, "SSH port")
		user       = flag.String("user", "", "SSH user (default: ssh client default)")
		keyPath    = flag.String("key", "", "SSH identity file (default: ssh-agent / ~/.ssh/config)")
		sudo       = flag.Bool("sudo", false, "wrap remote commands in sudo -n sh -c")
		mechanism  = flag.String("mechanism", "", "mechanism name, e.g. sysctl_set or file_content")
		phase      = flag.String("phase", "apply", "phase to inject failure at: capture, apply, or validate")
		paramsJSON = flag.String("params", "{}", "JSON-encoded mechanism params")
		timeout    = flag.Duration("timeout", 60*time.Second, "per-run timeout")
	)
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "kensa-fuzz: --host is required (or set KENSA_FUZZ_HOST)")
		os.Exit(1)
	}
	if *mechanism == "" {
		fmt.Fprintln(os.Stderr, "kensa-fuzz: --mechanism is required")
		os.Exit(1)
	}

	var params api.Params
	if err := json.Unmarshal([]byte(*paramsJSON), &params); err != nil {
		fmt.Fprintf(os.Stderr, "kensa-fuzz: invalid --params JSON: %v\n", err)
		os.Exit(1)
	}

	cfg := config{
		host:      *host,
		port:      *port,
		user:      *user,
		keyPath:   *keyPath,
		sudo:      *sudo,
		mechanism: *mechanism,
		phase:     *phase,
		params:    params,
		timeout:   *timeout,
	}

	exitCode := run(cfg)
	os.Exit(exitCode)
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
