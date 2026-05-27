package bootguard

import (
	"context"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// StateDir is where the guard stages its per-arming state on the target: the
// recorded trial identity, the applied param, and the confirm script.
const StateDir = "/var/lib/kensa/bootguard"

// runOK runs cmd and returns an error if the transport failed or the command
// exited non-zero.
func runOK(ctx context.Context, t api.Transport, cmd string) (*api.CommandResult, error) {
	res, err := t.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("bootguard: %q: transport error: %w", cmd, err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("bootguard: %q failed (exit %d): %s", cmd, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return res, nil
}
