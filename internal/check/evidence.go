package check

import (
	"context"
	"io/fs"

	"github.com/Hanalyx/kensa/api"
)

// maxEvidenceFieldBytes caps each captured stdout/stderr field. Raw check
// output (a full config dump, an audit ruleset) can be large; the cap keeps a
// ScanResult — and anything a consumer persists or embeds in OSCAL — bounded.
// Truncate-and-mark (not reject): the leading bytes are retained and
// [api.CheckEvidence.Truncated] is set, so the evidence stays usable.
const maxEvidenceFieldBytes = 64 * 1024 // 64 KiB

// Result is the outcome of running a rule's check: the boolean verdict, a
// human-readable detail string (unchanged from the legacy return), and the
// structured observation evidence — one [api.CheckEvidence] per command the
// check executed.
type Result struct {
	Passed   bool
	Detail   string
	Evidence []api.CheckEvidence
}

// recordingTransport wraps an [api.Transport], capturing every command and its
// result so [Run] can assemble observation evidence with NO change to any
// individual check function: the checks call transport.Run as before, and the
// wrapper records what they ran and observed. All other transport operations
// delegate unchanged, so the wrapper is transparent to agent mode and the
// control-channel-sensitivity contract.
type recordingTransport struct {
	inner api.Transport
	cmds  []commandRecord
}

type commandRecord struct {
	command   string
	stdout    string
	stderr    string
	exitCode  int
	truncated bool
}

func (r *recordingTransport) Run(ctx context.Context, cmd string) (*api.CommandResult, error) {
	res, err := r.inner.Run(ctx, cmd)
	rec := commandRecord{command: cmd}
	if res != nil {
		var t1, t2 bool
		rec.stdout, t1 = capEvidenceField(res.Stdout)
		rec.stderr, t2 = capEvidenceField(res.Stderr)
		rec.exitCode = res.ExitCode
		rec.truncated = t1 || t2
	}
	r.cmds = append(r.cmds, rec)
	return res, err
}

func (r *recordingTransport) Put(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	return r.inner.Put(ctx, localPath, remotePath, mode)
}

func (r *recordingTransport) Get(ctx context.Context, remotePath, localPath string) error {
	return r.inner.Get(ctx, remotePath, localPath)
}

func (r *recordingTransport) Close() error { return r.inner.Close() }

func (r *recordingTransport) ControlChannelSensitive() bool {
	return r.inner.ControlChannelSensitive()
}

// capEvidenceField truncates s at maxEvidenceFieldBytes, reporting whether it
// truncated.
func capEvidenceField(s string) (string, bool) {
	if len(s) <= maxEvidenceFieldBytes {
		return s, false
	}
	return s[:maxEvidenceFieldBytes], true
}

// buildEvidence assembles one [api.CheckEvidence] per recorded command from
// the check definition and the captured commands. Method comes from the
// check; Expected from its `expected` param when present. The raw Stdout is
// the authoritative observed state, so Actual is left empty here (a structured
// per-check Actual is a documented follow-up that would touch each check fn).
func buildEvidence(chk api.Check, recs []commandRecord) []api.CheckEvidence {
	if len(recs) == 0 {
		return nil
	}
	expected, _ := chk.Params["expected"].(string)
	out := make([]api.CheckEvidence, 0, len(recs))
	for _, rc := range recs {
		out = append(out, api.CheckEvidence{
			Method:    chk.Method,
			Command:   rc.command,
			Stdout:    rc.stdout,
			Stderr:    rc.stderr,
			ExitCode:  rc.exitCode,
			Expected:  expected,
			Truncated: rc.truncated,
		})
	}
	return out
}
