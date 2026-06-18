package kensa

import (
	// Register the standard apply-mechanism handlers whenever pkg/kensa is
	// used, so a service built via Default / DefaultWithEngineOptions /
	// DefaultWithTransportFactory can run Remediate / Rollback without the
	// caller importing any internal/ package. This is what makes the
	// remediation path usable by external consumers (issue #94); the kensa
	// CLI relies on the same bundle, so the two handler sets cannot diverge.
	_ "github.com/Hanalyx/kensa/pkg/kensa/handlers"
)
