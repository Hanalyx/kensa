package filepermissions

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// Capture records owner (name+uid), group (name+gid), mode (octal),
// and SELinux context (user:role:type:range) of the target path. The
// captured values let [Handler.Rollback] restore the exact prior
// state.
//
// Per handler-file-permissions spec C-05 / AC-04, Capture returns
// [api.ErrCaptureIncomplete] if the target does not exist or cannot
// be stat'd. The engine then aborts the transaction before any apply.
//
// Implementation: a single shell command that emits a deterministic
// pipe-separated record so the parser is unambiguous. We avoid `stat
// -c '%a|%U|%u|%G|%g'` plus a separate `ls -Z` because two round
// trips double the latency on a remote host; the combined `stat ; ls
// -Z` form completes in one transport call.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	// `stat -c` format: mode_octal|user|uid|group|gid
	// `ls -Z` provides SELinux context if present. We accept that
	// hosts without SELinux return "?" — the rollback handler treats
	// "?" as "no context to restore."
	cmd := fmt.Sprintf(
		`stat -c '%%a|%%U|%%u|%%G|%%g' %s && ls -Zd %s 2>/dev/null | awk '{print $1}'`,
		shellQuote(p.Path), shellQuote(p.Path),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("file_permissions: capture transport error: %w", err)
	}
	if !res.OK() {
		// stat failed — target doesn't exist or isn't accessible.
		return nil, fmt.Errorf("file_permissions: capture failed for %s: %w (stderr: %s)",
			p.Path, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}

	mode, owner, uid, group, gid, selinux, err := parseCaptureOutput(res.Stdout)
	if err != nil {
		return nil, fmt.Errorf("file_permissions: capture parse failed for %s: %w", p.Path, err)
	}

	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"path":            p.Path,
			"owner":           owner,
			"uid":             uid,
			"group":           group,
			"gid":             gid,
			"mode":            mode,
			"selinux_context": selinux,
		},
	}, nil
}

// parseCaptureOutput parses the two-line output of the capture
// command: stat line then SELinux context line.
func parseCaptureOutput(stdout string) (mode, owner, uid, group, gid, selinux string, err error) {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 1 {
		return "", "", "", "", "", "", fmt.Errorf("expected stat output, got empty stdout")
	}
	statFields := strings.Split(lines[0], "|")
	if len(statFields) != 5 {
		return "", "", "", "", "", "", fmt.Errorf("expected 5 stat fields, got %d (line=%q)", len(statFields), lines[0])
	}
	mode, owner, uid, group, gid = statFields[0], statFields[1], statFields[2], statFields[3], statFields[4]

	// Pad mode to 4 digits so "644" reads as "0644" — handler-
	// file-permissions spec AC-03 requires 4-digit octal.
	if len(mode) < 4 {
		mode = strings.Repeat("0", 4-len(mode)) + mode
	}

	if len(lines) >= 2 {
		selinux = strings.TrimSpace(lines[1])
		if selinux == "?" {
			selinux = "" // SELinux not present on this host
		}
	}
	return mode, owner, uid, group, gid, selinux, nil
}
