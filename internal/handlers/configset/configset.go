// Package configset implements the config_set handler: set a key-value
// pair in a configuration file, supporting three separator styles
// ("=", " = ", " "). Capture records the prior line for exact rollback.
// Spec: specs/handlers/config_set.spec.yaml.
package configset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name.
const mechanism = "config_set"

// validSeparators lists the accepted separator values.
var validSeparators = map[string]bool{
	"=":   true,
	" = ": true,
	" ":   true,
}

// Params is the decoded parameter struct for the config_set mechanism.
type Params struct {
	// File is the absolute path of the configuration file. Required.
	File string
	// Key is the configuration key to set. Required.
	Key string
	// Value is the desired value. Required.
	Value string
	// Separator is the key-value separator style. One of "=", " = ",
	// " ". Defaults to "=" when omitted.
	Separator string
}

var (
	errMissingFile  = errors.New("config_set: params missing required 'file'")
	errMissingKey   = errors.New("config_set: params missing required 'key'")
	errMissingValue = errors.New("config_set: params missing required 'value'")
)

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingFile
	}
	file, err := requireString(p, "file", errMissingFile)
	if err != nil {
		return nil, err
	}
	key, err := requireString(p, "key", errMissingKey)
	if err != nil {
		return nil, err
	}
	value, err := requireString(p, "value", errMissingValue)
	if err != nil {
		return nil, err
	}

	sep := "="
	if v, ok := p["separator"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("config_set: 'separator' must be a string")
		}
		if !validSeparators[s] {
			return nil, fmt.Errorf("config_set: 'separator' must be one of %q, %q, %q; got %q", "=", " = ", " ", s)
		}
		sep = s
	}
	return &Params{File: file, Key: key, Value: value, Separator: sep}, nil
}

// requireString extracts a non-empty string field from api.Params.
func requireString(p api.Params, key string, missing error) (string, error) {
	v, ok := p[key]
	if !ok {
		return "", missing
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", missing
	}
	return s, nil
}

// Handler implements the config_set mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "config_set".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply sets key=value in the target file. If the key already
// exists, the matching line is replaced. If absent, the line is appended.
//
// Uses a sed expression that handles commented-out and active keys.
// The pattern matches lines where the key appears at the start of a
// non-whitespace token (ignoring leading whitespace), handling both
// commented (#KEY=VALUE) and active (KEY=VALUE) forms. Only active lines
// are replaced; commented lines are left in place.
//
// Per spec C-01, apply is idempotent.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	targetLine := p.Key + p.Separator + p.Value

	// Build the sed replace+append command:
	// 1. Try to replace an existing active (non-commented) key line.
	// 2. If no replacement happened (grep check), append to end.
	//
	// We use a portable POSIX sed expression: match lines where the
	// key appears at the start (with optional leading whitespace) but
	// not preceded by '#'.
	//
	// Pattern notes:
	//   ^[[:space:]]*KEY followed by any separator char or space.
	//   We check grep first (simpler), then sed replace or append.
	sedPattern := fmt.Sprintf("^[[:space:]]*%s[[:space:]=]", sedEscape(p.Key))
	sedReplace := fmt.Sprintf("s|%s.*|%s|", sedPattern, sedEscape(targetLine))

	// Pipeline:
	//   1. grep to check if an active line exists.
	//   2. If yes: sed -i replace.
	//   3. If no: echo >> append.
	cmd := fmt.Sprintf(
		`if grep -qE %s %s 2>/dev/null; then `+
			`sed -i -E %s %s; `+
			`else echo %s >> %s; fi`,
		shellEscape(sedPattern),
		shellEscape(p.File),
		shellEscape(sedReplace),
		shellEscape(p.File),
		shellEscape(targetLine),
		shellEscape(p.File),
	)

	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("config_set: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("config_set: apply failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("config_set: set %s%s%s in %s", p.Key, p.Separator, p.Value, p.File),
	}, nil
}

// Capture records the prior state of the key in the file. Returns
// ErrCaptureIncomplete if the file does not exist.
// When the key is present, line_existed=true and prior_line contains the
// first matching active line. When absent, line_existed=false.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	// Check file existence first; fail early on absent config files.
	cmd := fmt.Sprintf(
		`if [ ! -e %[1]s ]; then printf '__KENSA_NOFILE__\n'; `+
			`elif grep -qE %[2]s %[1]s 2>/dev/null; then `+
			`grep -Em1 %[2]s %[1]s; `+
			`else printf '__KENSA_ABSENT__\n'; fi`,
		shellEscape(p.File),
		shellEscape(fmt.Sprintf("^[[:space:]]*%s[[:space:]=]", sedEscape(p.Key))),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("config_set: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("config_set: capture failed for %s: %w (stderr: %s)",
			p.File, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}

	stdout := strings.TrimSuffix(res.Stdout, "\n")
	switch stdout {
	case "__KENSA_NOFILE__":
		return nil, fmt.Errorf("config_set: capture failed for %s: %w (file does not exist)",
			p.File, api.ErrCaptureIncomplete)
	case "__KENSA_ABSENT__":
		return &api.PreState{
			Mechanism:  mechanism,
			Capturable: true,
			CapturedAt: time.Now().UTC(),
			Data: map[string]interface{}{
				"file":         p.File,
				"key":          p.Key,
				"separator":    p.Separator,
				"line_existed": false,
				"prior_line":   "",
			},
		}, nil
	default:
		return &api.PreState{
			Mechanism:  mechanism,
			Capturable: true,
			CapturedAt: time.Now().UTC(),
			Data: map[string]interface{}{
				"file":         p.File,
				"key":          p.Key,
				"separator":    p.Separator,
				"line_existed": true,
				"prior_line":   stdout,
			},
		}, nil
	}
}

// Rollback restores the prior line state per spec C-03.
// When line_existed=true, the current key line is replaced with prior_line
// using sed. When line_existed=false, the line appended by Apply is removed.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("config_set: rollback called with nil pre-state")
	}
	file, _ := pre.Data["file"].(string)
	key, _ := pre.Data["key"].(string)
	lineExisted, _ := pre.Data["line_existed"].(bool)
	priorLine, _ := pre.Data["prior_line"].(string)

	if file == "" || key == "" {
		return nil, errors.New("config_set: pre-state missing 'file' or 'key'")
	}

	sedPattern := fmt.Sprintf("^[[:space:]]*%s[[:space:]=]", sedEscape(key))

	var cmd string
	if lineExisted {
		// Replace current line with prior line verbatim.
		sedReplace := fmt.Sprintf("s|%s.*|%s|", sedPattern, sedEscape(priorLine))
		cmd = fmt.Sprintf("sed -i -E %s %s", shellEscape(sedReplace), shellEscape(file))
	} else {
		// Remove the line that was appended. Use grep -v to filter out
		// the key line and write back.
		cmd = fmt.Sprintf(
			"sed -i -E %s %s",
			shellEscape(fmt.Sprintf("/%s/d", sedPattern)),
			shellEscape(file),
		)
	}

	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("config_set: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("config_set: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("config_set: restored %s in %s (line_existed=%v)", key, file, lineExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// sedEscape escapes characters that have special meaning in basic sed
// patterns and replacement strings. Covers the common config-key chars.
func sedEscape(s string) string {
	// Escape pipe (our delimiter), backslash, dot, brackets, plus,
	// question mark, caret (within bracket), dollar in replacement.
	r := strings.NewReplacer(
		`\`, `\\`,
		`|`, `\|`,
		`.`, `\.`,
		`[`, `\[`,
		`]`, `\]`,
		`^`, `\^`,
		`$`, `\$`,
		`*`, `\*`,
		`+`, `\+`,
		`?`, `\?`,
		`(`, `\(`,
		`)`, `\)`,
	)
	return r.Replace(s)
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
