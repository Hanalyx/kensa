// Package api is the public contract for Kensa Go.
//
// Kensa is transactional configuration management for Linux. Every change
// it applies to a host runs through a four-phase transaction
// (capture → apply → validate → commit-or-rollback) with the atomicity,
// auditability, and reversibility commitments stated in
// docs/TRANSACTION_CONTRACT_V1.md. This package is the surface every
// external consumer — OpenWatch, the kensa CLI, third-party audit tools,
// and future AI agents — imports against.
//
// # The Top-Level Type
//
// [Kensa] composes every public capability into a single entry point.
// Construct one with [New]:
//
//	k, err := api.New(api.Config{StorePath: ".kensa/results.db"})
//	if err != nil { /* ... */ }
//	defer k.Close()
//
// Then call methods that map to the [OpenWatch] identities below.
//
// # Three Identities
//
// OpenWatch's three product identities (per docs/OPENWATCH_VISION.md) map
// directly to interfaces in this package:
//
//   - Eye           — historical transaction queries via [LogQuery] and
//     authenticity checks via [EnvelopeVerifier].
//   - Heartbeat     — live event subscription via [EventSubscriber].
//   - Control Plane — preview-then-execute via [Planner] and [Executor].
//
// The CLI consumes the same interfaces. Future AI agents talk to OpenWatch,
// not to this package directly (see docs/KENSA_OPENWATCH_RESPONSE_2026-04-14.md
// §4.1 for the rationale).
//
// # Versioning
//
// This package follows semantic versioning at v1 from commit 1. Breaking
// changes require a major-version bump. Additions — new methods, new
// optional fields on existing types, new functional options — are
// non-breaking and may land within v1. Deprecations use the
// "Deprecated:" marker and remain for at least one minor version before
// removal in v2.
//
// # Stubbed Implementations
//
// Methods whose engine-side implementations land in later milestones
// (see docs/KENSA_GO_DAY1_PLAN.md §11) return [ErrNotYetImplemented]
// until the feature ships. Signatures are stable from commit 1, so
// consumers may write production code against them today and see
// progressive feature enablement without source changes.
//
// # Reference Documentation
//
//   - docs/KENSA_VISION.md — category definition and four-phase primitive.
//   - docs/TECHNICAL_REMEDIATION_MP_V1.md — seven principles, transaction model.
//   - docs/CANONICAL_RULE_SCHEMA_V1.md — rule YAML contract with atomicity declaration.
//   - docs/TRANSACTION_CONTRACT_V1.md — customer-facing atomicity commitment.
//   - docs/KENSA_GO_DAY1_PLAN.md — this package's architectural contract and milestone schedule.
package api
