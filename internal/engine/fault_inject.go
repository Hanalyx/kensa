//go:build kensa_fault

package engine

import "os"

// faultExitAfterPrepare simulates a kill -9 immediately after the write-ahead
// barrier (the PREPARE journal+pre-state commit) when KENSA_FAULT_EXIT_AFTER_PREPARE=1.
// It is compiled ONLY under the kensa_fault build tag, used by the
// crash-recovery validation harness to prove an interrupted transaction is
// recoverable. os.Exit skips all defers, matching an abrupt kill.
func faultExitAfterPrepare() {
	if os.Getenv("KENSA_FAULT_EXIT_AFTER_PREPARE") == "1" {
		os.Exit(137)
	}
}

// faultExitAfterApply simulates a kill -9 after APPLY has mutated the host but
// before any terminal record is written — the case recovery must undo (the
// host is half-applied with no commit marker). KENSA_FAULT_EXIT_AFTER_APPLY=1.
func faultExitAfterApply() {
	if os.Getenv("KENSA_FAULT_EXIT_AFTER_APPLY") == "1" {
		os.Exit(137)
	}
}
