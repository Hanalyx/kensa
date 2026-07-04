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
	"os"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/fsatomic"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/valueguard"
)

// mechanism is the canonical handler name.
const mechanism = "pam_module_arg"

// pamFileMode is the fallback mode for a PAM config file that does not yet
// exist (root-writable, world-readable — the /etc/pam.d/* convention). When
// the file already exists the agent path preserves its actual mode via
// existingMode rather than forcing this value.
const pamFileMode = 0o644

// existingMode returns path's current mode bits, or pamFileMode when the file
// does not exist. The agent runs on the target host, so os.Stat is a local
// read. This preserves a non-0644 PAM file's mode on both apply and rollback
// (a hardened include MUST NOT be silently widened) — mirroring config_append.
func existingMode(path string) os.FileMode {
	if info, err := os.Stat(path); err == nil {
		return fsatomic.FileModeBits(info.Mode())
	}
	return pamFileMode
}

// absentSentinel marks a non-existent file in the shell capture read.
const absentSentinel = "__KENSA_ABSENT__"

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

	// module and arg are written into a PAM config line; a newline in either
	// injects extra PAM directives (security.md #13 class).
	if err := valueguard.NoControlCharsIn(map[string]string{
		"pam_module_arg module": module, "pam_module_arg arg": arg,
	}); err != nil {
		return nil, err
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
	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.applyKernel(ctx, ft, p)
	}
	return h.applyShell(ctx, transport, p)
}

// applyKernel edits each PAM file atomically through the kernelio funnel: read
// the whole file, transform it in Go (the sed-equivalent), and write it back
// via kernelio.WriteFile so the footprint recorder observes exactly the files
// it touches. A file with no change is left untouched (no spurious write).
func (h *Handler) applyKernel(ctx context.Context, ft kernelio.FileTransport, p *Params) (*api.StepResult, error) {
	var results []string
	for _, file := range p.Files {
		content, existed, err := ft.ReadFileIfExists(file)
		if err != nil {
			return nil, fmt.Errorf("pam_module_arg: read %s: %w", file, err)
		}
		if !existed {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("pam_module_arg: %s does not exist", file),
			}, nil
		}
		newContent, changed, terr := transformFile(p, content)
		if terr != nil {
			return &api.StepResult{Success: false, Detail: terr.Error()}, nil
		}
		if !changed {
			results = append(results, fmt.Sprintf("%s: no change (no-op)", file))
			continue
		}
		if werr := kernelio.WriteFile(ctx, ft, file, existingMode(file), []byte(newContent)); werr != nil {
			return nil, fmt.Errorf("pam_module_arg: write %s: %w", file, werr)
		}
		results = append(results, fmt.Sprintf("%s: %sd (kernel-io)", file, p.Action))
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("pam_module_arg: %s", strings.Join(results, "; ")),
	}, nil
}

// applyShell is the direct-SSH fallback: per-file sed -i.bak edits, unchanged.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, p *Params) (*api.StepResult, error) {
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
	// Single-quote the whole sed program via shellEscape so a single quote in
	// any rule-derived field (module/type/arg) cannot break out of the shell
	// quoting and inject a command. The kernelio agent path is pure-Go and
	// unaffected; this hardens the SSH-shell fallback.
	prog := fmt.Sprintf("/%s/s/$/ %s/", matchPart, appendArg)
	return fmt.Sprintf("sed -i.bak %s %s", shellEscape(prog), shellEscape(file))
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

	// Single-quote the whole sed program via shellEscape (see buildEnsureAppendCmd).
	var argPat string
	if isRegex {
		// Extended regex: use -E and strip the arg pattern.
		argPat = arg
		prog := fmt.Sprintf("/%s/s/ %s//g", lineMatch, argPat)
		return fmt.Sprintf("sed -E -i.bak %s %s", shellEscape(prog), shellEscape(file))
	}
	// Literal: escape for BRE sed.
	argPat = shellEscapeForSed(arg)
	prog := fmt.Sprintf("/%s/s/ %s//g", lineMatch, argPat)
	return fmt.Sprintf("sed -i.bak %s %s", shellEscape(prog), shellEscape(file))
}

// Capture records the WHOLE prior content and existence of each PAM file
// before Apply edits it, keyed by file path. Rollback restores the captured
// content verbatim (byte-perfect), which is robust across the agent and shell
// transports and immune to the line-number drift the prior grep-snapshot model
// risked. The read is dual-path: kernel-IO on the agent, shell cat otherwise.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	filesContent := make(map[string]interface{})
	filesExisted := make(map[string]interface{})
	for _, file := range p.Files {
		content, existed, rerr := h.readFile(ctx, transport, file)
		if rerr != nil {
			return nil, rerr
		}
		filesContent[file] = content
		filesExisted[file] = existed
	}

	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"module":        p.Module,
			"files_content": filesContent,
			"files_existed": filesExisted,
		},
	}, nil
}

// readFile returns a file's content and existence via the kernel-IO read
// (agent) or a shell cat with an absent sentinel.
func (h *Handler) readFile(ctx context.Context, transport api.Transport, file string) (string, bool, error) {
	if ft, ok := transport.(kernelio.FileTransport); ok {
		c, existed, err := ft.ReadFileIfExists(file)
		if err != nil {
			return "", false, fmt.Errorf("pam_module_arg: capture read %s: %w (%v)", file, api.ErrCaptureIncomplete, err)
		}
		return c, existed, nil
	}
	cmd := fmt.Sprintf("test -e %[1]s && cat %[1]s || printf '%[2]s'", shellEscape(file), absentSentinel)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return "", false, fmt.Errorf("pam_module_arg: capture transport error for %s: %w", file, err)
	}
	if !res.OK() {
		return "", false, fmt.Errorf("pam_module_arg: capture failed for %s: %w (stderr: %s)", file, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}
	if res.Stdout == absentSentinel {
		return "", false, nil
	}
	return res.Stdout, true, nil
}

// Rollback restores each PAM file to its captured pre-Apply state. For
// pre-states from the whole-file capture model (files_content) it rewrites the
// captured content verbatim — byte-perfect, dual-path (kernelio funnel on the
// agent, printf/rm on the shell). For legacy pre-states (files_snapshot, the
// grep-line model) it falls back to the prior sed line-restore so in-flight
// transactions captured before this change still roll back.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("pam_module_arg: rollback called with nil pre-state")
	}

	if content, ok := pre.Data["files_content"].(map[string]interface{}); ok {
		existed, _ := pre.Data["files_existed"].(map[string]interface{})
		return h.rollbackWhole(ctx, transport, content, existed)
	}

	snapshotRaw, ok := pre.Data["files_snapshot"]
	if !ok {
		return nil, errors.New("pam_module_arg: pre-state missing 'files_content' and 'files_snapshot'")
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
			// Replace line N with the original content; single-quote the whole
			// sed program via shellEscape so a single quote in the captured
			// line cannot break out of the shell quoting.
			prog := fmt.Sprintf("%ss/.*/%s/", lineNum, escapedContent)
			sedCmd := fmt.Sprintf("sed -i.bak %s %s", shellEscape(prog), shellEscape(file))
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

// rollbackWhole restores each captured file to its prior content (byte-perfect)
// — or removes it when it did not exist at capture — through the kernelio
// funnel on the agent, or printf/rm on the shell.
func (h *Handler) rollbackWhole(ctx context.Context, transport api.Transport, content, existed map[string]interface{}) (*api.RollbackResult, error) {
	var details []string
	for file, cRaw := range content {
		prior, _ := cRaw.(string)
		fileExisted := true // default true: a captured file we have content for
		if existed != nil {
			if e, ok := existed[file].(bool); ok {
				fileExisted = e
			}
		}
		if err := h.restoreFile(ctx, transport, file, prior, fileExisted); err != nil {
			return &api.RollbackResult{
				Success:    false,
				Detail:     fmt.Sprintf("pam_module_arg: rollback failed for %s: %v", file, err),
				ExecutedAt: time.Now().UTC(),
			}, nil
		}
		if fileExisted {
			details = append(details, fmt.Sprintf("%s: restored", file))
		} else {
			details = append(details, fmt.Sprintf("%s: removed (absent at capture)", file))
		}
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("pam_module_arg: rollback complete — %s", strings.Join(details, "; ")),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// restoreFile rewrites file to prior (or removes it when it was absent at
// capture), dual-path: kernelio funnel on the agent, printf/rm on the shell.
func (h *Handler) restoreFile(ctx context.Context, transport api.Transport, file, prior string, fileExisted bool) error {
	if ft, ok := transport.(kernelio.FileTransport); ok {
		if fileExisted {
			return kernelio.WriteFile(ctx, ft, file, existingMode(file), []byte(prior))
		}
		return kernelio.RemoveFile(ctx, ft, file)
	}
	var cmd string
	if fileExisted {
		cmd = fmt.Sprintf("printf '%%s' %s > %s", shellEscape(prior), shellEscape(file))
	} else {
		cmd = fmt.Sprintf("rm -f %s", shellEscape(file))
	}
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
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
