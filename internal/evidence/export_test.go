package evidence

import "github.com/Hanalyx/kensa/api"

// CanonicalForTest exposes canonicalize() to package-external
// tests. Lives in *_test.go so it doesn't ship in production
// binaries — tests that need to inspect the canonical bytes
// (for domain-separation checks, key-order checks, etc.) reach
// it through this shim.
func CanonicalForTest(envelope *api.EvidenceEnvelope) ([]byte, error) {
	return canonicalize(envelope)
}
