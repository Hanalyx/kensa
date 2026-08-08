package main

import (
	"context"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// TestOpenAgentOptions_AgentPathAndOptOut pins the contract that makes a
// rollback the mechanical inverse of the apply it undoes.
//
// Handlers choose their implementation by type-asserting the transport, so a
// rollback without the agent silently sends every handler to its shell
// fallback. rollback used to do exactly that, because it never opened an agent
// at all: audit_rule_set then applied over netlink and rolled back through
// `augenrules --load`, which recompiles /etc/audit/audit.rules and leaves an
// audit.rules.prev the apply never created.
//
// Two halves, both checkable without a host:
//
//   - with KENSA_NO_AGENT=1 it opts out cleanly, returning no engine options
//     and a usable cleanup, exactly as remediate does;
//   - without it, the agent path IS attempted, which an unreachable host
//     proves by failing rather than silently returning no options.
//
// @spec cli-rollback-session-aware
// @ac AC-18
func TestOpenAgentOptions_AgentPathAndOptOut(t *testing.T) {
	t.Run("cli-rollback-session-aware/AC-18", func(t *testing.T) {})
	cfg := api.HostConfig{Hostname: "203.0.113.1", User: "nobody", Port: 22}

	t.Setenv("KENSA_NO_AGENT", "1")
	opts, cleanup, err := openAgentOptions(context.Background(), cfg)
	if err != nil {
		t.Fatalf("opt-out returned an error: %v", err)
	}
	if len(opts) != 0 {
		t.Errorf("opt-out returned %d engine option(s), want 0", len(opts))
	}
	if cleanup == nil {
		t.Error("opt-out returned a nil cleanup; callers defer it unconditionally")
	} else {
		cleanup() // must be safe to call
	}

	// 203.0.113.0/24 is TEST-NET-3 (RFC 5737) and is not routable, so this
	// cannot reach a real host. An error here is the point: it proves the
	// agent path was taken rather than skipped.
	t.Setenv("KENSA_NO_AGENT", "")
	// Bounded: the point is that a connection was ATTEMPTED, not how long the
	// network takes to give up on an unroutable address.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	opts, cleanup, err = openAgentOptions(ctx, cfg)
	if err == nil {
		t.Error("expected an error connecting to an unroutable host; " +
			"a nil error means the agent path was not attempted")
	}
	if len(opts) != 0 {
		t.Errorf("failed agent open returned %d option(s), want 0", len(opts))
	}
	if cleanup == nil {
		t.Error("failed agent open returned a nil cleanup")
	} else {
		cleanup()
	}
}
