// Package api is the public contract for Kensa Go.
//
// Every external consumer — OpenWatch, the kensa CLI, third-party audit
// tools, and future AI agents — imports from this package. The internal
// engine (internal/...) implements these interfaces but is freely
// refactorable.
//
// # Versioning
//
// The api/ package follows semver v1 from commit 1. Breaking changes
// require a major-version bump. Additions (new methods, new optional
// fields on existing types) are non-breaking and may land within v1.
// Deprecations are marked with `// Deprecated:` and retained for at
// least one minor version before removal in v2.
//
// # Stubbed Implementations
//
// Methods whose implementations land in later milestones (see
// docs/KENSA_GO_DAY1_PLAN.md §11) return ErrNotYetImplemented until the
// feature ships. The signatures themselves are stable — consumers can
// write code against them immediately and see progressive feature
// enablement without source changes.
//
// # OpenWatch-Facing Surfaces
//
// OpenWatch's three identities (Eye, Heartbeat, Control Plane) map
// directly to interfaces in this package:
//
//   - Eye          -> LogQuery (historical transaction queries)
//   - Heartbeat    -> EventSubscriber (live event stream)
//   - Control Plane -> Planner + Executor (preview-then-execute)
//
// The Kensa top-level type composes all three into a single entry point.
//
// # Reference Documentation
//
//   - docs/KENSA_VISION.md              — category definition
//   - docs/TECHNICAL_REMEDIATION_MP_V1.md — seven principles, transaction model
//   - docs/TRANSACTION_CONTRACT_V1.md   — customer-facing atomicity commitment
//   - docs/KENSA_GO_DAY1_PLAN.md        — this package's architectural contract
package api
