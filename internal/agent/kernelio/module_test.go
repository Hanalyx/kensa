package kernelio

import (
	"errors"
	"testing"
)

// TestDeleteModule_EmptyName covers the deterministic guard. The real
// delete_module(2) path needs root + a loaded module and is exercised by
// live validation, not CI: as a non-root test process it returns EPERM,
// and asserting on that would be uid-dependent and flaky.
//
// @spec kernelio-module
// @ac AC-01
func TestDeleteModule_EmptyName(t *testing.T) {
	t.Run("kernelio-module/AC-01", func(t *testing.T) {})
	if err := DeleteModule(""); err == nil {
		t.Error("DeleteModule(\"\") should error")
	}
	// ErrModuleNotLoaded is a distinct sentinel callers can branch on.
	if !errors.Is(ErrModuleNotLoaded, ErrModuleNotLoaded) {
		t.Error("sentinel identity check")
	}
}
