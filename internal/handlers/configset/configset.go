// Package configset implements the config_set handler: set a key-value
// pair in a configuration file, supporting three separator styles
// ("=", " = ", " "). Capture records the prior line for exact rollback.
// Spec: specs/handlers/config_set.spec.yaml.
package configset

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/agent/fsatomic"
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
// **Phase 2 P-004 migration (2026-05-11)**: agent-mode uses Go's
// regexp package + fsatomic.AtomicReplace for crash-safe line
// rewrites. The Go pattern mirrors sed's
// `^[[:space:]]*KEY[[:space:]=]` semantics: line-start, optional
// leading whitespace, literal key, then space-or-equals. Active
// lines (no leading `#`) are replaced; commented lines are left
// alone. Behavioral-parity tests cover the sed semantics this
// path replicates.
//
// Per spec C-01, apply is idempotent.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if vErr := fsatomic.ValidatePath(p.File); vErr != nil {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("config_set: %v", vErr),
		}, nil
	}

	targetLine := p.Key + p.Separator + p.Value

	if afs, ok := transport.(fsatomic.Transport); ok {
		// Agent-mode: Go regex + fsatomic.AtomicReplace.
		original, readErr := os.ReadFile(p.File)
		if readErr != nil {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("config_set: read %s: %v", p.File, readErr),
			}, nil
		}
		newContent, changed, replaceErr := setKeyInContent(string(original), p.Key, targetLine)
		if replaceErr != nil {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("config_set: rewrite %s: %v", p.File, replaceErr),
			}, nil
		}
		if !changed && string(original) == newContent {
			// Idempotent: file already has the desired line.
			return &api.StepResult{
				Success: true,
				Detail:  fmt.Sprintf("config_set: %s already had %s%s%s (no change)", p.File, p.Key, p.Separator, p.Value),
			}, nil
		}
		// Preserve the file's existing mode.
		info, statErr := os.Stat(p.File)
		if statErr != nil {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("config_set: stat %s: %v", p.File, statErr),
			}, nil
		}
		// `fsatomic.FileModeBits` preserves setuid/setgid/sticky
		// in addition to the 9 perm bits. A plain `& 0o7777`
		// would silently drop them because Go encodes those
		// special bits in HIGH positions (1<<22, 1<<23, 1<<20),
		// outside the 0o7777 mask. Sed -i preserves all 12.
		if err := afs.AtomicReplace(ctx, p.File, fsatomic.FileModeBits(info.Mode()), []byte(newContent)); err != nil {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("config_set: AtomicReplace %s: %v", p.File, err),
			}, nil
		}
		return &api.StepResult{
			Success: true,
			Detail:  fmt.Sprintf("config_set: atomically set %s%s%s in %s", p.Key, p.Separator, p.Value, p.File),
		}, nil
	}

	// Direct-SSH fallback: shell pipeline.
	sedPattern := fmt.Sprintf("^[[:space:]]*%s[[:space:]=]", sedEscape(p.Key))
	sedReplace := fmt.Sprintf("s|%s.*|%s|", sedPattern, sedEscape(targetLine))
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

// activeLineRegex builds the Go regexp that matches the sed
// pattern `^[[:space:]]*KEY[[:space:]=]` per-line. Returns
// the compiled regex (multi-line mode set via (?m)).
//
// Sed `-E` with default `LC_ALL=C` interprets `[[:space:]]`
// as exactly `\t` and ` `. Go's `[[:space:]]` matches the
// broader set `\t\n\v\f\r ` per regexp/syntax — divergence
// on CRLF files (where `\r` would match in Go but not sed).
// Spelling the class as `[\t ]` makes the Go regex
// byte-equivalent to sed's intent and fixes the post-merge
// security review's P1-5 divergence.
//
// Sed `^` = line-start under -E with default delimiter;
// Go needs (?m). Key is regexp.QuoteMeta'd to handle dotted
// keys safely.
func activeLineRegex(key string) (*regexp.Regexp, error) {
	pat := `(?m)^[\t ]*` + regexp.QuoteMeta(key) + `[\t =].*$`
	return regexp.Compile(pat)
}

// setKeyInContent applies the config_set transformation to
// `content`: if an active (non-commented) line matching `key`
// exists, replace it (all matches; matches sed behavior) with
// `targetLine`. If no match, append `targetLine` (plus a
// trailing newline if needed). Returns (newContent, changed,
// err) — `changed` is true iff bytes differ from input.
//
// Preserves byte-exact content for non-matching lines
// including their line endings (CRLF preserved per FMA Q1.c).
func setKeyInContent(content, key, targetLine string) (string, bool, error) {
	re, err := activeLineRegex(key)
	if err != nil {
		return "", false, err
	}
	// First check if any match exists. ReplaceAllString
	// returns the unchanged string if no match; we want to
	// distinguish that from the all-matches-replaced case
	// so we can append in the no-match branch.
	matches := re.FindAllStringIndex(content, -1)
	if len(matches) > 0 {
		// Replace every matching line with targetLine.
		// Note: targetLine MAY contain regex metacharacters
		// (e.g., $ in `EnableX $value`). ReplaceAllString
		// expands `$N` references; use ReplaceAllLiteralString
		// to disable expansion.
		newContent := re.ReplaceAllLiteralString(content, targetLine)
		return newContent, newContent != content, nil
	}
	// No match — append. Preserve existing trailing-newline
	// state per FMA Q1.b: if content ends with \n, append
	// targetLine + \n; if content has no trailing newline,
	// add a newline before appending so the new line is on
	// its own line.
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + targetLine + "\n", true, nil
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

	// Phase 2 P-004 migration: agent-mode uses Go regex +
	// AtomicReplace for symmetric line-oriented rollback.
	// The capture contract is preserved: capture records
	// `prior_line` (the matching line as it was pre-Apply),
	// not full file content. Rollback uses Go regex to find
	// the current key line and restore (or remove) it.
	if afs, ok := transport.(fsatomic.Transport); ok {
		original, readErr := os.ReadFile(file)
		if readErr != nil {
			return &api.RollbackResult{
				Success:    false,
				Detail:     fmt.Sprintf("config_set: rollback read %s: %v", file, readErr),
				ExecutedAt: time.Now().UTC(),
			}, nil
		}
		var newContent string
		var rewriteErr error
		if lineExisted {
			// Replace current key line(s) with priorLine.
			re, reErr := activeLineRegex(key)
			if reErr != nil {
				rewriteErr = reErr
			} else {
				newContent = re.ReplaceAllLiteralString(string(original), priorLine)
			}
		} else {
			// Remove the line that Apply appended. The
			// appended line is an active key line by
			// construction (Apply wrote targetLine without
			// leading whitespace or `#`). Replace the entire
			// matching line including its trailing newline so
			// the file doesn't grow blank-lines on each
			// Apply/Rollback cycle.
			removeRe, removeErr := regexp.Compile(`(?m)^[\t ]*` + regexp.QuoteMeta(key) + `[\t =].*\n?`)
			if removeErr != nil {
				rewriteErr = removeErr
			} else {
				newContent = removeRe.ReplaceAllString(string(original), "")
			}
		}
		if rewriteErr != nil {
			return &api.RollbackResult{
				Success:    false,
				Detail:     fmt.Sprintf("config_set: rollback regex %s: %v", file, rewriteErr),
				ExecutedAt: time.Now().UTC(),
			}, nil
		}
		info, statErr := os.Stat(file)
		if statErr != nil {
			return &api.RollbackResult{
				Success:    false,
				Detail:     fmt.Sprintf("config_set: rollback stat %s: %v", file, statErr),
				ExecutedAt: time.Now().UTC(),
			}, nil
		}
		// `fsatomic.FileModeBits` preserves setuid/setgid/sticky
		// (see Apply for the same fix).
		if err := afs.AtomicReplace(ctx, file, fsatomic.FileModeBits(info.Mode()), []byte(newContent)); err != nil {
			return &api.RollbackResult{
				Success:    false,
				Detail:     fmt.Sprintf("config_set: rollback AtomicReplace %s: %v", file, err),
				ExecutedAt: time.Now().UTC(),
			}, nil
		}
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("config_set: atomically rolled back %s (line_existed=%v)", file, lineExisted),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	// Direct-SSH fallback: shell pipeline.
	sedPattern := fmt.Sprintf("^[[:space:]]*%s[[:space:]=]", sedEscape(key))

	var cmd string
	if lineExisted {
		sedReplace := fmt.Sprintf("s|%s.*|%s|", sedPattern, sedEscape(priorLine))
		cmd = fmt.Sprintf("sed -i -E %s %s", shellEscape(sedReplace), shellEscape(file))
	} else {
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
