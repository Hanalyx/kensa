// Package pammodulearg implements the pam_module_arg handler:
// ensure or remove an argument from a PAM module line across one or
// more PAM configuration files. Uses sed with a backup (-i.bak) and
// captures the pre-edit lines for rollback.
// Spec: specs/handlers/pam_module_arg.spec.yaml.
package pammodulearg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name.
const mechanism = "pam_module_arg"

// Params is the decoded parameter struct for the pam_module_arg
// mechanism.
type Params struct {
	// Action is "ensure" (add arg if missing) or "remove" (strip arg).
	// Required.
	Action string
	// Module is the PAM module filename, e.g. "pam_unix.so". Required.
	Module string
	// Arg is the argument string or extended-regex pattern. Required.
	Arg string
	// ArgRegex, when true, treats Arg as an extended regex for sed.
	ArgRegex bool
	// Files is the list of PAM config files to edit. Required.
	Files []string
	// Type is an optional PAM line type filter ("auth", "account",
	// "password", "session"). Empty string means match all types.
	Type string
}

var (
	errMissingAction = errors.New("pam_module_arg: params missing required 'action'")
	errInvalidAction = errors.New("pam_module_arg: 'action' must be 'ensure' or 'remove'")
	errMissingModule = errors.New("pam_module_arg: params missing required 'module'")
	errMissingArg    = errors.New("pam_module_arg: params missing required 'arg'")
	errMissingFiles  = errors.New("pam_module_arg: params missing required 'files'")
)

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingAction
	}

	actionRaw, ok := p["action"]
	if !ok {
		return nil, errMissingAction
	}
	action, ok := actionRaw.(string)
	if !ok || action == "" {
		return nil, errMissingAction
	}
	if action != "ensure" && action != "remove" {
		return nil, errInvalidAction
	}

	moduleRaw, ok := p["module"]
	if !ok {
		return nil, errMissingModule
	}
	module, ok := moduleRaw.(string)
	if !ok || module == "" {
		return nil, errMissingModule
	}

	argRaw, ok := p["arg"]
	if !ok {
		return nil, errMissingArg
	}
	arg, ok := argRaw.(string)
	if !ok {
		return nil, errMissingArg
	}

	filesRaw, ok := p["files"]
	if !ok {
		return nil, errMissingFiles
	}
	var files []string
	switch fv := filesRaw.(type) {
	case []string:
		files = fv
	case []interface{}:
		for i, item := range fv {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("pam_module_arg: 'files[%d]' must be a string", i)
			}
			files = append(files, s)
		}
	default:
		return nil, fmt.Errorf("pam_module_arg: 'files' must be a list of strings")
	}
	if len(files) == 0 {
		return nil, errMissingFiles
	}

	out := &Params{
		Action: action,
		Module: module,
		Arg:    arg,
		Files:  files,
	}

	if v, ok := p["arg_regex"]; ok {
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("pam_module_arg: 'arg_regex' must be a bool")
		}
		out.ArgRegex = b
	}
	if v, ok := p["type"]; ok {
		t, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("pam_module_arg: 'type' must be a string")
		}
		out.Type = t
	}

	return out, nil
}

// Handler implements the pam_module_arg mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "pam_module_arg".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply modifies the PAM files per the action:
//   - "ensure": if the module line does not already have the arg, append it.
//   - "remove": strip the arg (or regex match) from lines containing the module.
//
// Uses sed -i.bak so the original files are preserved on the host for
// manual recovery. The .bak copy is not part of the rollback path —
// rollback restores from the captured line snapshot instead.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, file := range p.Files {
		detail, applyErr := applyToFile(ctx, transport, p, file)
		if applyErr != nil {
			return nil, applyErr
		}
		results = append(results, detail)
	}

	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("pam_module_arg: %s", strings.Join(results, "; ")),
	}, nil
}

// applyToFile applies the action to a single PAM file. Returns a
// human-readable detail string on success, or an error.
func applyToFile(ctx context.Context, transport api.Transport, p *Params, file string) (string, error) {
	// Build the module-line match pattern. If Type is set, anchor the
	// pattern to that PAM type column.
	modulePattern := shellEscapeForSed(p.Module)
	typeFilter := ""
	if p.Type != "" {
		typeFilter = fmt.Sprintf("^[[:space:]]*%s[[:space:]]", p.Type)
	}

	switch p.Action {
	case "ensure":
		// Check if any matching module line already has the arg.
		argPattern := p.Arg
		checkCmd := buildEnsureCheckCmd(file, typeFilter, modulePattern, argPattern, p.ArgRegex)
		res, err := transport.Run(ctx, checkCmd)
		if err != nil {
			return "", fmt.Errorf("pam_module_arg: ensure check transport error for %s: %w", file, err)
		}
		if res.ExitCode == 0 {
			// Arg already present.
			return fmt.Sprintf("%s: arg already present (no-op)", file), nil
		}

		// Append the arg to matching module lines.
		appendArg := shellEscapeForSed(p.Arg)
		sedCmd := buildEnsureAppendCmd(file, typeFilter, modulePattern, appendArg)
		res, err = transport.Run(ctx, sedCmd)
		if err != nil {
			return "", fmt.Errorf("pam_module_arg: ensure append transport error for %s: %w", file, err)
		}
		if !res.OK() {
			return "", fmt.Errorf("pam_module_arg: ensure append failed for %s (exit %d): %s", file, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		return fmt.Sprintf("%s: arg appended", file), nil

	case "remove":
		sedCmd := buildRemoveCmd(file, typeFilter, modulePattern, p.Arg, p.ArgRegex)
		res, err := transport.Run(ctx, sedCmd)
		if err != nil {
			return "", fmt.Errorf("pam_module_arg: remove transport error for %s: %w", file, err)
		}
		if !res.OK() {
			return "", fmt.Errorf("pam_module_arg: remove failed for %s (exit %d): %s", file, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		return fmt.Sprintf("%s: arg removed", file), nil

	default:
		return "", fmt.Errorf("pam_module_arg: unknown action %q", p.Action)
	}
}

// buildEnsureCheckCmd returns a grep command that exits 0 if the arg is
// already present on a module line.
func buildEnsureCheckCmd(file, typeFilter, modulePattern, arg string, isRegex bool) string {
	var grepFlag string
	if isRegex {
		grepFlag = "-E"
	} else {
		grepFlag = "-F"
	}
	if typeFilter != "" {
		return fmt.Sprintf("grep -P %s %s %s 2>/dev/null | grep %s %s",
			shellEscape(typeFilter+`.*`+modulePattern),
			shellEscape(file), grepFlag, grepFlag, shellEscape(arg))
	}
	return fmt.Sprintf("grep %s %s %s 2>/dev/null | grep %s %s",
		shellEscape(modulePattern), shellEscape(file), grepFlag, grepFlag, shellEscape(arg))
}

// buildEnsureAppendCmd returns a sed command that appends arg to
// matching module lines.
func buildEnsureAppendCmd(file, typeFilter, modulePattern, appendArg string) string {
	var matchPart string
	if typeFilter != "" {
		matchPart = typeFilter + `.*` + modulePattern
	} else {
		matchPart = modulePattern
	}
	// Append arg at end of each matching line: s/\(pattern.*\)/\1 arg/
	return fmt.Sprintf("sed -i.bak '/%s/s/$/ %s/' %s", matchPart, appendArg, shellEscape(file))
}

// buildRemoveCmd returns a sed command that strips arg (or regex) from
// matching module lines.
func buildRemoveCmd(file, typeFilter, modulePattern, arg string, isRegex bool) string {
	var lineMatch string
	if typeFilter != "" {
		lineMatch = typeFilter + `.*` + modulePattern
	} else {
		lineMatch = modulePattern
	}

	var argPat string
	if isRegex {
		// Extended regex: use -E and strip the arg pattern.
		argPat = arg
		return fmt.Sprintf("sed -E -i.bak '/%s/s/ %s//g' %s", lineMatch, argPat, shellEscape(file))
	}
	// Literal: escape for BRE sed.
	argPat = shellEscapeForSed(arg)
	return fmt.Sprintf("sed -i.bak '/%s/s/ %s//g' %s", lineMatch, argPat, shellEscape(file))
}

// Capture records the affected lines from each PAM file before editing,
// keyed by file path. Rollback restores these lines via sed.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	snapshot := make(map[string]interface{})
	for _, file := range p.Files {
		// Capture lines containing the module name (with optional type filter).
		grepPattern := p.Module
		if p.Type != "" {
			grepPattern = p.Type + `.*` + p.Module
		}
		cmd := fmt.Sprintf("grep -n %s %s 2>/dev/null || true", shellEscape(grepPattern), shellEscape(file))
		res, err := transport.Run(ctx, cmd)
		if err != nil {
			return nil, fmt.Errorf("pam_module_arg: capture transport error for %s: %w", file, err)
		}
		snapshot[file] = res.Stdout
	}

	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"module":         p.Module,
			"files_snapshot": snapshot,
		},
	}, nil
}

// Rollback restores the captured PAM file lines by reinserting the
// original content via sed line replacement. Idempotent.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("pam_module_arg: rollback called with nil pre-state")
	}

	snapshotRaw, ok := pre.Data["files_snapshot"]
	if !ok {
		return nil, errors.New("pam_module_arg: pre-state missing 'files_snapshot'")
	}
	snapshot, ok := snapshotRaw.(map[string]interface{})
	if !ok {
		return nil, errors.New("pam_module_arg: pre-state 'files_snapshot' has unexpected type")
	}

	var details []string
	for file, contentRaw := range snapshot {
		content, _ := contentRaw.(string)
		if content == "" {
			// No affected lines captured — restore from .bak if present.
			restoreCmd := fmt.Sprintf("test -f %s.bak && cp -f %s.bak %s || true",
				shellEscape(file), shellEscape(file), shellEscape(file))
			res, err := transport.Run(ctx, restoreCmd)
			if err != nil {
				return nil, fmt.Errorf("pam_module_arg: rollback transport error for %s: %w", file, err)
			}
			if !res.OK() {
				return &api.RollbackResult{
					Success:    false,
					Detail:     fmt.Sprintf("pam_module_arg: rollback bak-restore failed for %s (exit %d): %s", file, res.ExitCode, strings.TrimSpace(res.Stderr)),
					ExecutedAt: time.Now().UTC(),
				}, nil
			}
			details = append(details, fmt.Sprintf("%s: restored from .bak", file))
			continue
		}

		// Parse the grep -n output (format: "linenum:content") and
		// restore each line via sed address replacement.
		lines := strings.Split(strings.TrimSpace(content), "\n")
		for _, greppedLine := range lines {
			if greppedLine == "" {
				continue
			}
			colonIdx := strings.Index(greppedLine, ":")
			if colonIdx < 0 {
				continue
			}
			lineNum := greppedLine[:colonIdx]
			lineContent := greppedLine[colonIdx+1:]
			escapedContent := shellEscapeForSed(lineContent)
			// Replace line N with the original content.
			sedCmd := fmt.Sprintf("sed -i.bak '%ss/.*/%s/' %s", lineNum, escapedContent, shellEscape(file))
			res, err := transport.Run(ctx, sedCmd)
			if err != nil {
				return nil, fmt.Errorf("pam_module_arg: rollback sed transport error for %s line %s: %w", file, lineNum, err)
			}
			if !res.OK() {
				return &api.RollbackResult{
					Success:    false,
					Detail:     fmt.Sprintf("pam_module_arg: rollback sed failed for %s line %s (exit %d): %s", file, lineNum, res.ExitCode, strings.TrimSpace(res.Stderr)),
					ExecutedAt: time.Now().UTC(),
				}, nil
			}
		}
		details = append(details, fmt.Sprintf("%s: lines restored", file))
	}

	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("pam_module_arg: rollback complete — %s", strings.Join(details, "; ")),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellEscapeForSed escapes special BRE/sed characters for safe use
// inside a sed expression (outside of single-quoted shell strings).
func shellEscapeForSed(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`.`, `\.`,
		`[`, `\[`,
		`]`, `\]`,
		`^`, `\^`,
		`$`, `\$`,
		`*`, `\*`,
		`/`, `\/`,
		`&`, `\&`,
	)
	return r.Replace(s)
}
