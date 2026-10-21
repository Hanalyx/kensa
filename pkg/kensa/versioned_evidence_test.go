package kensa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/evidence"
	"github.com/Hanalyx/kensa/internal/handler"
)

type evidenceNoAudit struct{}

func (evidenceNoAudit) EmitPhase(string, string, bool) {}

// @spec cli-verify-subcommand
// @ac AC-06 AC-07
// @spec evidence-envelope
// @ac AC-12
func TestVersionedSigningPipeline(t *testing.T) {
	t.Log("// @spec cli-verify-subcommand")
	t.Log("// @ac AC-07")
	ctx := context.Background()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	binaries := map[string]string{}
	for _, name := range []string{"kensa", "kensa-keygen"} {
		binary := filepath.Join(dir, name)
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", binary, "../../cmd/"+name)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", name, err, output)
		}
		binaries[name] = binary
	}
	cmd := exec.Command(binaries["kensa-keygen"], "--out", keys)
	var keygenStdout, keygenStderr bytes.Buffer
	cmd.Stdout = &keygenStdout
	cmd.Stderr = &keygenStderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("actual keygen: %v stdout=%s stderr=%s", err, keygenStdout.String(), keygenStderr.String())
	}
	t.Logf("keygen exit=0 stdout=%q stderr=%q", keygenStdout.String(), keygenStderr.String())
	private, err := filepath.Glob(filepath.Join(keys, "*.priv"))
	if err != nil || len(private) != 1 {
		t.Fatal("keygen private file missing")
	}
	t.Setenv("KENSA_SIGNING_KEY", private[0])
	signer, err := evidence.LoadSigner(private[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"committed", "rollback", "errored"} {
		t.Run(kind, func(t *testing.T) {
			reg := handler.NewRegistry()
			good := &engine.FakeHandler{HandlerName: "fixture_ok", IsCapturable: true, CapturePreState: &api.PreState{Data: map[string]any{"large": int64(9007199254740993)}, CapturedAt: time.Now().UTC()}, RollbackResult: &api.RollbackResult{Success: true, Detail: "fixture restored"}}
			bad := &engine.FakeHandler{HandlerName: "fixture_fail", IsCapturable: true, ApplyErr: errors.New("induced fixture apply failure")}
			reg.Register(good)
			reg.Register(bad)
			db := filepath.Join(t.TempDir(), "evidence.db")
			factory := &fakeFactory{}
			// Use the standard key/store builder and a fixture transport. No real
			// handler or remote connection is used; this is not restoration evidence.
			svc, err := DefaultWithTransportFactory(ctx, db, factory, engine.WithRegistry(reg), engine.WithAuditEmitter(evidenceNoAudit{}))
			if err != nil {
				t.Fatal(err)
			}
			txn := &api.Transaction{ID: uuid.New(), RuleID: "fixture-evidence", HostID: "offline-fixture", Severity: "high", Transactional: true, StartedAt: time.Now().UTC(), Deadline: time.Now().Add(time.Minute), Steps: []api.Step{{Index: 0, Mechanism: "fixture_ok"}}}
			if kind == "rollback" {
				txn.Steps = append(txn.Steps, api.Step{Index: 1, Mechanism: "fixture_fail"})
			}
			if kind == "errored" {
				txn.Steps[0].Mechanism = "unknown_fixture"
			}
			result, runErr := svc.Transact(ctx, api.HostConfig{Hostname: "offline-fixture"}, txn)
			if result == nil || result.Envelope == nil {
				t.Fatalf("engine result: %v %+v", runErr, result)
			}
			if result.Envelope.SchemaVersion != "v2" {
				t.Fatalf("production version=%q", result.Envelope.SchemaVersion)
			}
			if factory.connects.Load() != 1 {
				t.Fatal("fixture transport was not used")
			}
			if kind == "errored" {
				if result.Status != api.StatusErrored || len(result.Envelope.Signature) != 0 || good.ApplyCalls != 0 {
					t.Fatalf("unsigned failure sentinel changed: %+v", result)
				}
				svc.Close()
				return
			}
			if runErr != nil {
				t.Fatal(runErr)
			}
			if kind == "committed" && result.Status != api.StatusCommitted {
				t.Fatalf("commit status=%s", result.Status)
			}
			if kind == "rollback" && (result.Status != api.StatusRollbackFailed || len(result.Envelope.RollbackResults) != 1 || good.RollbackCalls != 1) {
				t.Fatalf("rollback status/results changed: %+v", result)
			}
			verification, err := signer.Verify(result.Envelope)
			if err != nil || !verification.Valid {
				t.Fatalf("returned engine signature: %v", err)
			}
			serialized, err := json.Marshal(result.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			// Envelope owns a copy of the rollback result, independent of the
			// handler/result object that operational code retains.
			if kind == "rollback" {
				original := result.Envelope.RollbackResults[0].Detail
				good.RollbackResult.Detail = "changed operational copy"
				result.RollbackResults[0].Detail = "changed result copy"
				if result.Envelope.RollbackResults[0].Detail != original {
					t.Fatal("signed envelope aliases operational results")
				}
			}
			if err := svc.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := DefaultWithTransportFactory(ctx, db, &fakeFactory{}, engine.WithRegistry(reg), engine.WithAuditEmitter(evidenceNoAudit{}))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			record, err := reopened.TransactionLog().Get(ctx, result.TransactionID)
			if err != nil {
				t.Fatal(err)
			}
			v, err := reopened.VerifyEnvelope(record.Envelope)
			if err != nil || !v.Valid || v.EnvelopeHash != verification.EnvelopeHash {
				t.Fatalf("SQLite key-file verification: %v %+v", err, v)
			}
			persisted, err := json.Marshal(record.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(serialized, persisted) {
				t.Fatalf("persisted envelope bytes changed\n%s\n%s", serialized, persisted)
			}
			path := filepath.Join(dir, kind+".json")
			if err := os.WriteFile(path, persisted, 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(binaries["kensa"], "verify", path, "--trust-dir", keys, "--format", "json")
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("actual CLI: %v %s %s", err, stdout.String(), stderr.String())
			}
			var body map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["valid"] != true || body["accepted"] != true || body["rollback_results_authenticated"] != true {
				t.Fatalf("CLI policy: %s", stdout.String())
			}
			t.Logf("%s returned/SQLite signature/hash verified; actual CLI exit=0 stdout=%s stderr=%q", kind, stdout.String(), stderr.String())
			if output := os.Getenv("PT04_EVIDENCE_DIR"); output != "" {
				if err := reopened.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(output, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(output, kind+".json"), persisted, 0600); err != nil {
					t.Fatal(err)
				}
				database, err := os.ReadFile(db)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(output, kind+".db"), database, 0600); err != nil {
					t.Fatal(err)
				}
				public, err := os.ReadFile(filepath.Join(keys, signer.KeyID()+".pub"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(output, signer.KeyID()+".pub"), public, 0644); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
