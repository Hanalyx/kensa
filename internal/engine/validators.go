package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// Validator is a post-apply check run during the VALIDATE phase. If any
// Validator reports !Passed, the engine rolls back the transaction.
//
// The engine runs validators after every successful apply phase. Built-in
// validators (for example, [ControlChannelValidator]) are activated
// automatically when relevant. Custom validators can be injected via
// [WithValidators].
type Validator interface {
	// Name is the validator's stable identifier, surfaced in
	// [api.ValidatorResult.Name] for logs, UI, and audit records.
	Name() string

	// Validate runs the post-apply check and returns the outcome. It
	// MUST NOT mutate the host. Errors (transport failures, command
	// timeouts) should surface as !Passed with a descriptive Detail,
	// not as panics or unhandled errors.
	Validate(ctx context.Context, transport api.Transport, txn *api.Transaction) api.ValidatorResult
}

// WithValidators adds custom validators to the engine. They run during the
// VALIDATE phase in addition to built-in validators. Validators injected
// here run for every transaction against this engine instance.
//
// For per-transaction validators (for example, a service-health check whose
// service name comes from a rule parameter), callers can build a Validator
// whose Name/Validate read from closure state.
func WithValidators(vs ...Validator) Option {
	return func(e *Engine) { e.validators = append(e.validators, vs...) }
}

// ControlChannelValidator verifies that the SSH control channel is still
// reachable after a control-channel-affecting change. It runs `true` on the
// transport and treats any failure as a validate failure.
//
// The engine activates this validator automatically when the transaction
// contains a control-channel-sensitive mechanism (see
// [controlChannelMechanisms] in preflight.go). Callers do not need to
// inject it explicitly.
type ControlChannelValidator struct{}

// Name returns "control_channel_reachability".
func (ControlChannelValidator) Name() string { return "control_channel_reachability" }

// Validate runs `true` on the transport. A non-zero exit code or transport
// error means the control channel was disrupted and the engine should roll
// back.
func (ControlChannelValidator) Validate(ctx context.Context, transport api.Transport, _ *api.Transaction) api.ValidatorResult {
	res, err := transport.Run(ctx, "true")
	if err != nil {
		return api.ValidatorResult{
			Name:     "control_channel_reachability",
			Passed:   false,
			Detail:   fmt.Sprintf("transport error: %v", err),
			Evidence: "",
		}
	}
	if !res.OK() {
		return api.ValidatorResult{
			Name:     "control_channel_reachability",
			Passed:   false,
			Detail:   fmt.Sprintf("control channel probe failed (exit %d)", res.ExitCode),
			Evidence: res.Stderr,
		}
	}
	return api.ValidatorResult{
		Name:   "control_channel_reachability",
		Passed: true,
		Detail: "control channel reachable",
	}
}

// ServiceHealthValidator checks that a given service is active after apply.
// Use this for transactions that restart or reconfigure a service so the
// validate phase can confirm the service came back up.
//
// Example (PAM change that restarts sshd):
//
//	engine.New(engine.WithValidators(engine.ServiceHealthValidator{Service: "sshd"}))
type ServiceHealthValidator struct {
	// Service is the systemd unit name to check (e.g. "sshd" or "sshd.service").
	// Required.
	Service string
}

// Name returns "service_health:<service>".
func (v ServiceHealthValidator) Name() string {
	return "service_health:" + v.Service
}

// Validate runs `systemctl is-active <service>`. Exit 0 means active.
// Any other exit code (inactive, failed, activating) is a validate failure.
func (v ServiceHealthValidator) Validate(ctx context.Context, transport api.Transport, _ *api.Transaction) api.ValidatorResult {
	if v.Service == "" {
		return api.ValidatorResult{
			Name:   "service_health:(empty)",
			Passed: false,
			Detail: "ServiceHealthValidator.Service is empty",
		}
	}
	cmd := "systemctl is-active " + shellEscape(v.Service)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return api.ValidatorResult{
			Name:     v.Name(),
			Passed:   false,
			Detail:   fmt.Sprintf("transport error: %v", err),
			Evidence: "",
		}
	}
	if !res.OK() {
		return api.ValidatorResult{
			Name:     v.Name(),
			Passed:   false,
			Detail:   fmt.Sprintf("service %q is not active (exit %d, state: %q)", v.Service, res.ExitCode, strings.TrimSpace(res.Stdout)),
			Evidence: res.Stdout,
		}
	}
	return api.ValidatorResult{
		Name:     v.Name(),
		Passed:   true,
		Detail:   fmt.Sprintf("service %q is active", v.Service),
		Evidence: res.Stdout,
	}
}

// ConfigSyntaxValidator runs an arbitrary syntax-check command after apply.
// Use this for transactions that modify configuration files where the
// relevant daemon provides a built-in syntax check (e.g. `sshd -t`,
// `nginx -t`, `httpd -t`).
//
// Example (sshd config change):
//
//	engine.New(engine.WithValidators(engine.ConfigSyntaxValidator{
//	    ValidatorName: "sshd_syntax",
//	    Command:       "sshd -t",
//	}))
type ConfigSyntaxValidator struct {
	// ValidatorName is the stable identifier for this validator.
	// Defaults to "config_syntax" when empty.
	ValidatorName string
	// Command is the syntax-check command to run on the target host.
	// Required. Must be a non-mutating check (exit 0 = valid, non-zero = invalid).
	Command string
}

// Name returns ValidatorName or "config_syntax" when empty.
func (v ConfigSyntaxValidator) Name() string {
	if v.ValidatorName != "" {
		return v.ValidatorName
	}
	return "config_syntax"
}

// Validate runs Command on the transport. Exit 0 means valid syntax.
// Any non-zero exit code is a validate failure.
func (v ConfigSyntaxValidator) Validate(ctx context.Context, transport api.Transport, _ *api.Transaction) api.ValidatorResult {
	if v.Command == "" {
		return api.ValidatorResult{
			Name:   v.Name(),
			Passed: false,
			Detail: "ConfigSyntaxValidator.Command is empty",
		}
	}
	res, err := transport.Run(ctx, v.Command)
	if err != nil {
		return api.ValidatorResult{
			Name:     v.Name(),
			Passed:   false,
			Detail:   fmt.Sprintf("transport error: %v", err),
			Evidence: "",
		}
	}
	if !res.OK() {
		return api.ValidatorResult{
			Name:     v.Name(),
			Passed:   false,
			Detail:   fmt.Sprintf("syntax check %q failed (exit %d)", v.Command, res.ExitCode),
			Evidence: res.Stdout + "\n" + res.Stderr,
		}
	}
	return api.ValidatorResult{
		Name:     v.Name(),
		Passed:   true,
		Detail:   fmt.Sprintf("syntax check %q passed", v.Command),
		Evidence: res.Stdout,
	}
}

// shellEscape wraps s in single quotes for safe inclusion in a shell command.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
