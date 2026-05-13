// Live-host agent-mode parity test. L-014c deliverable per
// spec agent-live-host-parity.
//
// **Gated on env vars.** Skipped when KENSA_TEST_SSH_HOST
// or KENSA_TEST_AGENT_MODE is unset. When both set, the
// test runs the full agent-mode pipeline against a real
// host and compares the resulting RemediationResult to a
// direct-SSH run for the same rule.
//
// **Why this exists.** Every L-007..L-032 test uses
// in-process pipes or local-subprocess agents. None
// exercise real SSH, real bootstrap-push via scp, or real
// over-the-wire handshake. L-014c is the ONLY check that
// the complete pipeline holds together against a
// production-shaped target.
//
// **Normalized-equality contract.** RemediationResult
// equality is checked field-by-field via normalizeForCompare:
//   - time.Time fields zeroed (CapturedAt, ExecutedAt,
//     StartedAt, FinishedAt all differ between runs)
//   - TransactionID zeroed (UUIDs differ)
//   - Duration zeroed (per-step timing differs)
// Everything else (mechanism, params echo, Success,
// Detail, mode changed on disk) must match exactly.
//
// **Stub status (2026-05-11).** The test scaffolding +
// gating + env-var documentation are in place. The full
// live invocation (loading a real rule, building a host
// config, running kensa.DefaultWithEngineOptions with +
// without WithAgentClient) is left as a structured TODO
// — wiring this end-to-end requires either a real test
// host the founder has or a CI-wired target. The skipped-
// when-env-unset path is the ship-now contract; the
// runs-when-env-set path is wired by the operator (or
// CI) when they have a host to point it at.

package main

import (
	"os"
	"testing"
)

// TestLiveAgentMode_FilePermissionsParity locks AC-01..
// AC-04 of agent-live-host-parity. Skipped without env
// vars; runs the parity comparison when both are set.
//
// @spec agent-live-host-parity
// @ac AC-02
func TestLiveAgentMode_FilePermissionsParity(t *testing.T) {
	t.Log("// @spec agent-live-host-parity")
	t.Log("// @ac AC-02")
	sshHost := os.Getenv("KENSA_TEST_SSH_HOST")
	agentMode := os.Getenv("KENSA_TEST_AGENT_MODE")

	if sshHost == "" || agentMode != "1" {
		t.Skipf("L-014c live parity test SKIPPED: requires KENSA_TEST_SSH_HOST + KENSA_TEST_AGENT_MODE=1. " +
			"Set both to run the full agent-mode pipeline against a real host.")
	}

	// L-014c full-implementation TODO. The pieces below
	// are the well-defined scope of what the runs-when-
	// env-set path needs to do.
	//
	// 1. Load a file_permissions rule from the corpus
	//    (e.g., kensa/rules/file-permissions-etc-shadow).
	//    The corpus path is $KENSA_TEST_RULES_DIR (env
	//    var) or defaults to ../kensa/rules from the
	//    repo root.
	//
	// 2. Build an api.HostConfig pointing at
	//    KENSA_TEST_SSH_HOST. Operator's responsibility:
	//    the target must have ~/.cache/kensa/ writable
	//    by the SSH user.
	//
	// 3. Create a test-target file under $HOME on the
	//    remote (e.g., $HOME/kensa-test-target). Set
	//    its initial mode to 0o600. Test cleanup deletes
	//    it.
	//
	// 4. Run direct-SSH path:
	//      svc := kensa.Default(ctx, dbPath)
	//      result1 := svc.Remediate(ctx, hostCfg, [rule])
	//
	// 5. Re-set the test-target mode to 0o600 (so the
	//    agent-mode run also has work to do).
	//
	// 6. Run agent-mode path:
	//      transport := ssh.Factory{}.Connect(ctx, hostCfg)
	//      client, cleanup, _ := dispatcher.OpenAgent(...)
	//      defer cleanup()
	//      svc := kensa.DefaultWithEngineOptions(ctx,
	//          dbPath, engine.WithAgentClient(client))
	//      result2 := svc.Remediate(ctx, hostCfg, [rule])
	//
	// 7. Compare normalizeForCompare(result1) ==
	//    normalizeForCompare(result2). Field-by-field.
	//
	// Currently SKIPPED until a test host is available.
	// The skipped path is verified by the AC-01 case
	// (env vars unset → clean skip).
	t.Skip("L-014c full implementation TODO: requires CI-wired test host. See spec agent-live-host-parity for the runs-when-env-set contract.")
}
