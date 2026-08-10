// Package api is the public contract for Kensa.
//
// Kensa is transactional configuration management for Linux. Every change
// it applies to a host runs through a four-phase transaction
// (capture → apply → validate → commit-or-rollback) that commits only when
// validation passes and otherwise restores the captured pre-state. This
// package is the surface every
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
// OpenWatch's three product identities map directly to interfaces in this
// package:
//
//   - Eye           — historical transaction queries via [LogQuery] and
//     authenticity checks via [EnvelopeVerifier].
//   - Heartbeat     — live event subscription via [EventSubscriber].
//   - Control Plane — preview-then-execute via [Planner] and [Executor].
//
// The CLI consumes the same interfaces. Agents talk to OpenWatch rather than
// to this package, so policy and approval stay in one place instead of being
// reimplemented by every caller.
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
// Methods whose engine-side implementations have not landed yet return
// [ErrNotYetImplemented]. Signatures are stable from commit 1, so
// consumers may write production code against them today and see
// progressive feature enablement without source changes.
package api
