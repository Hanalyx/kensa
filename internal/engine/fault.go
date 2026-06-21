//go:build !kensa_fault

package engine

// faultExitAfterPrepare and faultExitAfterApply are no-ops in normal builds.
// The crash-injection variants (build tag kensa_fault) are compiled only for
// the recovery validation harness, so the released binary can never exit here.
func faultExitAfterPrepare() {}
func faultExitAfterApply()   {}
