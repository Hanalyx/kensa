// Package dconfset implements the dconf_set handler:
// configure a dconf key in a system-level profile, optionally locking
// it to prevent user override, and run `dconf update`.
// Capturable: records the prior file content for rollback.
// Spec: specs/handlers/dconf_set.spec.yaml.
//
// Dual path: when the transport implements kernelio.FileTransport (agent
// mode on the target host) the handler writes the dconf profile / keyfile
// snippet / lock files atomically (fsatomic), instead of the shell
// printf + mkdir pipeline. The `dconf update` compile step DELIBERATELY
// stays shell on both paths — it is the dconf toolchain's job to compile
// the keyfile drop-ins into the binary database, exactly as mount keeps
// the remount on mount(8) and audit keeps the load on augenrules. (The
// migration doc's "D-Bus to ca.desrt.dconf" does not apply here: that is
// the user-session dconf API, whereas dconf_set manages system policy,
// which is file-based.) Both paths write byte-identical files and record
// an identical PreState shape.
package dconfset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
)

// mechanism is the canonical handler name.
const mechanism = "dconf_set"

// dconfDirMode / dconfFileMode are the modes for dconf config dirs/files
// (root-owned, world-readable).
const (
	dconfDirMode  = 0o755
	dconfFileMode = 0o644
)

// dconfPaths bundles the four filesystem paths a dconf_set apply touches.
type dconfPaths struct {
	profile string
	dbDir   string
	snippet string
	locksD  string
	lock    string
}

// pathsFor computes the dconf paths for the decoded params.
func pathsFor(p *Params) dconfPaths {
	dbDir := fmt.Sprintf("/etc/dconf/db/%s.d", p.DB)
	return dconfPaths{
		profile: fmt.Sprintf("/etc/dconf/profile/%s", p.DB),
		dbDir:   dbDir,
		snippet: fmt.Sprintf("%s/%s", dbDir, p.File),
		locksD:  fmt.Sprintf("%s/locks", dbDir),
		lock:    fmt.Sprintf("%s/locks/%s", dbDir, p.File),
	}
}

// profileBody / snippetBody / lockBody render the file contents, shared by
// both paths so they write byte-identical files.
func profileBody(db string) string { return fmt.Sprintf("user\nsystem-db:%s\n", db) }

func snippetBody(p *Params) string {
	valueStr := p.Value
	if p.ValueType != "" {
		valueStr = fmt.Sprintf("%s(%s)", p.ValueType, p.Value)
	}
	return fmt.Sprintf("[%s]\n%s=%s\n", p.Schema, p.Key, valueStr)
}

func lockBody(p *Params) string { return fmt.Sprintf("/%s/%s\n", p.Schema, p.Key) }

// defaultDB is the dconf database name used when the rule does not
// specify one.
const defaultDB = "local"

// Params is the decoded parameter struct for the dconf_set mechanism.
type Params struct {
	// Schema is the dconf schema path, e.g. "org/gnome/login-screen".
	// Required.
	Schema string
	// Key is the key name within the schema. Required.
	Key string
	// Value is the value to set. Required.
	Value string
	// File is the snippet filename, e.g. "00-security-settings".
	// Required.
	File string
	// DB is the dconf database name. Defaults to "local".
	DB string
	// Lock, when true, writes a lock file to prevent user override.
	Lock bool
	// ValueType is an optional GVariant type hint, e.g. "uint32",
	// "bool". When set, the value is written as type(value).
	ValueType string
}

var (
	errMissingSchema = errors.New("dconf_set: params missing required 'schema'")
	errMissingKey    = errors.New("dconf_set: params missing required 'key'")
	errMissingValue  = errors.New("dconf_set: params missing required 'value'")
	errMissingFile   = errors.New("dconf_set: params missing required 'file'")
)

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingSchema
	}

	schemaRaw, ok := p["schema"]
	if !ok {
		return nil, errMissingSchema
	}
	schema, ok := schemaRaw.(string)
	if !ok || schema == "" {
		return nil, errMissingSchema
	}

	keyRaw, ok := p["key"]
	if !ok {
		return nil, errMissingKey
	}
	key, ok := keyRaw.(string)
	if !ok || key == "" {
		return nil, errMissingKey
	}

	valueRaw, ok := p["value"]
	if !ok {
		return nil, errMissingValue
	}
	value, ok := valueRaw.(string)
	if !ok {
		return nil, errMissingValue
	}

	fileRaw, ok := p["file"]
	if !ok {
		return nil, errMissingFile
	}
	file, ok := fileRaw.(string)
	if !ok || file == "" {
		return nil, errMissingFile
	}

	out := &Params{
		Schema: schema,
		Key:    key,
		Value:  value,
		File:   file,
		DB:     defaultDB,
	}

	if v, ok := p["db"]; ok {
		db, ok := v.(string)
		if !ok || db == "" {
			return nil, fmt.Errorf("dconf_set: 'db' must be a non-empty string")
		}
		out.DB = db
	}
	if v, ok := p["lock"]; ok {
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("dconf_set: 'lock' must be a bool")
		}
		out.Lock = b
	}
	if v, ok := p["value_type"]; ok {
		vt, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("dconf_set: 'value_type' must be a string")
		}
		out.ValueType = vt
	}

	return out, nil
}

// Handler implements the dconf_set mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "dconf_set".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply creates/updates the dconf profile and snippet files, optionally
// writes a lock file, then runs `dconf update`.
//
// File layout created:
//
//	/etc/dconf/profile/<db>                — profile (user\nsystem-db:<db>\n)
//	/etc/dconf/db/<db>.d/<file>            — key=value snippet
//	/etc/dconf/db/<db>.d/locks/<file>      — lock (optional)
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.applyKernel(ctx, ft, transport, p)
	}
	return h.applyShell(ctx, transport, p)
}

// applyKernel writes the profile / snippet / lock files atomically and
// runs `dconf update` via the shell (the compile step).
func (h *Handler) applyKernel(ctx context.Context, ft kernelio.FileTransport, transport api.Transport, p *Params) (*api.StepResult, error) {
	paths := pathsFor(p)

	// 1. Ensure the profile exists (create-if-absent, matching the shell).
	if _, existed, rerr := ft.ReadFileIfExists(paths.profile); rerr != nil {
		return nil, fmt.Errorf("dconf_set: read profile: %w", rerr)
	} else if !existed {
		if werr := ft.AtomicReplace(ctx, paths.profile, dconfFileMode, []byte(profileBody(p.DB))); werr != nil {
			return nil, fmt.Errorf("dconf_set: profile write: %w", werr)
		}
	}
	// 2. db.d dir + snippet.
	if err := ft.MkdirAll(paths.dbDir, dconfDirMode); err != nil {
		return nil, fmt.Errorf("dconf_set: mkdir db.d: %w", err)
	}
	if err := ft.AtomicReplace(ctx, paths.snippet, dconfFileMode, []byte(snippetBody(p))); err != nil {
		return nil, fmt.Errorf("dconf_set: snippet write: %w", err)
	}
	// 3. Optional lock.
	if p.Lock {
		if err := ft.MkdirAll(paths.locksD, dconfDirMode); err != nil {
			return nil, fmt.Errorf("dconf_set: mkdir locks: %w", err)
		}
		if err := ft.AtomicReplace(ctx, paths.lock, dconfFileMode, []byte(lockBody(p))); err != nil {
			return nil, fmt.Errorf("dconf_set: lock write: %w", err)
		}
	}
	// 4. Compile via the dconf toolchain (stays shell).
	if res, err := transport.Run(ctx, "dconf update"); err != nil {
		return nil, fmt.Errorf("dconf_set: dconf update transport error: %w", err)
	} else if !res.OK() {
		return &api.StepResult{Success: false, Detail: fmt.Sprintf("dconf_set: dconf update failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("dconf_set: %s/%s written to %s and dconf updated (kernel-io)", p.Schema, p.Key, paths.snippet),
	}, nil
}

// applyShell creates/updates the dconf files via shell and runs dconf update.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, p *Params) (*api.StepResult, error) {
	profilePath := fmt.Sprintf("/etc/dconf/profile/%s", p.DB)
	dbDir := fmt.Sprintf("/etc/dconf/db/%s.d", p.DB)
	snippetPath := fmt.Sprintf("%s/%s", dbDir, p.File)
	locksDir := fmt.Sprintf("%s/locks", dbDir)
	lockPath := fmt.Sprintf("%s/%s", locksDir, p.File)

	// 1. Ensure the profile file exists.
	createProfileCmd := fmt.Sprintf(
		"test -f %s || printf %s > %s",
		shellEscape(profilePath),
		shellEscape(fmt.Sprintf("user\nsystem-db:%s\n", p.DB)),
		shellEscape(profilePath),
	)
	if res, err := transport.Run(ctx, createProfileCmd); err != nil {
		return nil, fmt.Errorf("dconf_set: profile create transport error: %w", err)
	} else if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("dconf_set: profile create failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}

	// 2. Ensure the db.d directory exists.
	mkdirCmd := fmt.Sprintf("mkdir -p %s", shellEscape(dbDir))
	if res, err := transport.Run(ctx, mkdirCmd); err != nil {
		return nil, fmt.Errorf("dconf_set: mkdir transport error: %w", err)
	} else if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("dconf_set: mkdir failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}

	// 3. Write the key snippet: [schema]\nkey=value\n
	// Normalise schema: dconf uses "/" as separator internally but the
	// ini-style snippet uses the schema path as a section header with
	// surrounding brackets. We keep it as-is per the spec.
	valueStr := p.Value
	if p.ValueType != "" {
		valueStr = fmt.Sprintf("%s(%s)", p.ValueType, p.Value)
	}
	snippetContent := fmt.Sprintf("[%s]\n%s=%s\n", p.Schema, p.Key, valueStr)
	writeSnippetCmd := fmt.Sprintf("printf %s > %s", shellEscape(snippetContent), shellEscape(snippetPath))
	if res, err := transport.Run(ctx, writeSnippetCmd); err != nil {
		return nil, fmt.Errorf("dconf_set: snippet write transport error: %w", err)
	} else if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("dconf_set: snippet write failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}

	// 4. Optionally write a lock file.
	if p.Lock {
		mkLocksCmd := fmt.Sprintf("mkdir -p %s", shellEscape(locksDir))
		if res, err := transport.Run(ctx, mkLocksCmd); err != nil {
			return nil, fmt.Errorf("dconf_set: locks mkdir transport error: %w", err)
		} else if !res.OK() {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("dconf_set: locks mkdir failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			}, nil
		}

		lockContent := fmt.Sprintf("/%s/%s\n", p.Schema, p.Key)
		writeLockCmd := fmt.Sprintf("printf %s > %s", shellEscape(lockContent), shellEscape(lockPath))
		if res, err := transport.Run(ctx, writeLockCmd); err != nil {
			return nil, fmt.Errorf("dconf_set: lock write transport error: %w", err)
		} else if !res.OK() {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("dconf_set: lock write failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			}, nil
		}
	}

	// 5. Run dconf update.
	if res, err := transport.Run(ctx, "dconf update"); err != nil {
		return nil, fmt.Errorf("dconf_set: dconf update transport error: %w", err)
	} else if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("dconf_set: dconf update failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}

	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("dconf_set: %s/%s=%s written to %s and dconf updated", p.Schema, p.Key, valueStr, snippetPath),
	}, nil
}

// Capture records the current snippet file content (if any) so
// rollback can restore or remove it.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	snippetPath := fmt.Sprintf("/etc/dconf/db/%s.d/%s", p.DB, p.File)

	if ft, ok := transport.(kernelio.FileTransport); ok {
		content, existed, rerr := ft.ReadFileIfExists(snippetPath)
		if rerr != nil {
			return nil, fmt.Errorf("dconf_set: capture read %s: %w (%v)", snippetPath, api.ErrCaptureIncomplete, rerr)
		}
		return preState(snippetPath, content, existed), nil
	}

	// Read existing file content; fall back sentinel when absent.
	checkCmd := fmt.Sprintf("test -f %s && cat %s || printf '__KENSA_ABSENT__'",
		shellEscape(snippetPath), shellEscape(snippetPath))
	res, err := transport.Run(ctx, checkCmd)
	if err != nil {
		return nil, fmt.Errorf("dconf_set: capture transport error: %w", err)
	}

	priorContent := res.Stdout
	fileExisted := true
	if priorContent == "__KENSA_ABSENT__" {
		priorContent = ""
		fileExisted = false
	}
	return preState(snippetPath, priorContent, fileExisted), nil
}

// preState builds the canonical PreState shape used by both capture paths.
func preState(filePath, priorContent string, fileExisted bool) *api.PreState {
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"file_path":     filePath,
			"prior_content": priorContent,
			"file_existed":  fileExisted,
		},
	}
}

// Rollback restores the prior snippet file content (or removes it if
// it was absent before Apply ran), then runs `dconf update`. Idempotent.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("dconf_set: rollback called with nil pre-state")
	}
	filePath, _ := pre.Data["file_path"].(string)
	priorContent, _ := pre.Data["prior_content"].(string)
	fileExisted, _ := pre.Data["file_existed"].(bool)

	if filePath == "" {
		return nil, errors.New("dconf_set: pre-state missing 'file_path'")
	}

	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.rollbackKernel(ctx, ft, transport, filePath, priorContent, fileExisted)
	}

	var restoreCmd string
	if fileExisted {
		restoreCmd = fmt.Sprintf("printf %s > %s", shellEscape(priorContent), shellEscape(filePath))
	} else {
		restoreCmd = fmt.Sprintf("rm -f %s", shellEscape(filePath))
	}

	if res, err := transport.Run(ctx, restoreCmd); err != nil {
		return nil, fmt.Errorf("dconf_set: rollback restore transport error: %w", err)
	} else if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("dconf_set: rollback restore failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	// Re-run dconf update to apply the restored (or removed) file.
	if res, err := transport.Run(ctx, "dconf update"); err != nil {
		return nil, fmt.Errorf("dconf_set: rollback dconf update transport error: %w", err)
	} else if !res.OK() {
		return &api.RollbackResult{
			Success:        false,
			PartialRestore: true,
			Detail:         fmt.Sprintf("dconf_set: file restored but dconf update failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt:     time.Now().UTC(),
		}, nil
	}

	action := "restored"
	if !fileExisted {
		action = "removed (was absent before apply)"
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("dconf_set: %s %s and dconf updated", filePath, action),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackKernel restores or removes the snippet atomically, then runs
// `dconf update` (the compile step, stays shell).
func (h *Handler) rollbackKernel(ctx context.Context, ft kernelio.FileTransport, transport api.Transport, filePath, priorContent string, fileExisted bool) (*api.RollbackResult, error) {
	if fileExisted {
		if err := ft.AtomicReplace(ctx, filePath, dconfFileMode, []byte(priorContent)); err != nil {
			return nil, fmt.Errorf("dconf_set: rollback restore: %w", err)
		}
	} else if err := ft.AtomicRemove(ctx, filePath); err != nil {
		return nil, fmt.Errorf("dconf_set: rollback remove: %w", err)
	}
	if res, err := transport.Run(ctx, "dconf update"); err != nil {
		return nil, fmt.Errorf("dconf_set: rollback dconf update transport error: %w", err)
	} else if !res.OK() {
		return &api.RollbackResult{
			Success:        false,
			PartialRestore: true,
			Detail:         fmt.Sprintf("dconf_set: file restored but dconf update failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt:     time.Now().UTC(),
		}, nil
	}
	action := "restored"
	if !fileExisted {
		action = "removed (was absent before apply)"
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("dconf_set: %s %s and dconf updated (kernel-io)", filePath, action),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
