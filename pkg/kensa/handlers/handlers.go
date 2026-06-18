// Package handlers is the public, blank-importable bundle of Kensa's
// standard apply-mechanism handlers. Importing it (for side effects)
// registers every handler with the global registry — handler.Default() —
// so that a service built via pkg/kensa.Default* can run Remediate /
// Rollback.
//
// External consumers cannot import Kensa's internal/handlers/* packages
// (Go forbids cross-module internal/ imports), and the handlers register
// only via init() side effects of those packages. Before this bundle,
// pkg/kensa.DefaultWithTransportFactory(...).Remediate(...) failed at
// preflight with `mechanism "file_permissions" is not registered` for any
// external caller (issue #94). pkg/kensa imports this bundle so the
// Default* constructors register the standard handlers automatically; the
// kensa CLI relies on the same bundle, so the two handler sets cannot
// diverge.
//
// Consumers building a Kensa via api.New{...} directly (bypassing the
// Default* constructors) can blank-import this package themselves:
//
//	import _ "github.com/Hanalyx/kensa/pkg/kensa/handlers"
//
// THIS IS THE SINGLE SOURCE OF TRUTH for the registered handler set. A new
// mechanism under internal/handlers/<name>/ MUST be added here too; the
// completeness test (handlers_test.go) fails CI otherwise.
package handlers

import (
	// Each blank import registers one apply-mechanism handler via its
	// init() side effect (handler.Register(New())). Registering the full
	// set is this package's entire purpose — see the package doc and
	// issue #94.
	_ "github.com/Hanalyx/kensa/internal/handlers/aptabsent"
	_ "github.com/Hanalyx/kensa/internal/handlers/aptpresent"
	_ "github.com/Hanalyx/kensa/internal/handlers/auditruleset"
	_ "github.com/Hanalyx/kensa/internal/handlers/authselectfeatureenable"
	_ "github.com/Hanalyx/kensa/internal/handlers/commandexec"
	_ "github.com/Hanalyx/kensa/internal/handlers/configappend"
	_ "github.com/Hanalyx/kensa/internal/handlers/configset"
	_ "github.com/Hanalyx/kensa/internal/handlers/configsetdropin"
	_ "github.com/Hanalyx/kensa/internal/handlers/cronjob"
	_ "github.com/Hanalyx/kensa/internal/handlers/cryptopolicyset"
	_ "github.com/Hanalyx/kensa/internal/handlers/cryptopolicysubpolicy"
	_ "github.com/Hanalyx/kensa/internal/handlers/dconfset"
	_ "github.com/Hanalyx/kensa/internal/handlers/fileabsent"
	_ "github.com/Hanalyx/kensa/internal/handlers/filecontent"
	_ "github.com/Hanalyx/kensa/internal/handlers/filepermissions"
	_ "github.com/Hanalyx/kensa/internal/handlers/grubparameterremove"
	_ "github.com/Hanalyx/kensa/internal/handlers/grubparameterset"
	_ "github.com/Hanalyx/kensa/internal/handlers/kernelmoduledisable"
	_ "github.com/Hanalyx/kensa/internal/handlers/manual"
	_ "github.com/Hanalyx/kensa/internal/handlers/mountoptionset"
	_ "github.com/Hanalyx/kensa/internal/handlers/packageabsent"
	_ "github.com/Hanalyx/kensa/internal/handlers/packagepresent"
	_ "github.com/Hanalyx/kensa/internal/handlers/pammodulearg"
	_ "github.com/Hanalyx/kensa/internal/handlers/pammoduleconfigure"
	_ "github.com/Hanalyx/kensa/internal/handlers/selinuxbooleanset"
	_ "github.com/Hanalyx/kensa/internal/handlers/servicedisabled"
	_ "github.com/Hanalyx/kensa/internal/handlers/serviceenabled"
	_ "github.com/Hanalyx/kensa/internal/handlers/servicemasked"
	_ "github.com/Hanalyx/kensa/internal/handlers/sysctlset"
)
