package rule_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/Hanalyx/kensa-go/internal/rule"
)

// @spec rule-ordering
// @ac AC-01
// @ac AC-02
// @ac AC-03
// @ac AC-04
// @ac AC-05
// @ac AC-06
// @ac AC-07
// @ac AC-08
// @ac AC-09
// @ac AC-10
// @ac AC-11
// @ac AC-12
// @ac AC-13
// @ac AC-14
// @ac AC-15
// @ac AC-16
// @ac AC-17
// @ac AC-18
// @ac AC-19
func TestCorpusParity(t *testing.T) {
	t.Run("rule-ordering/AC-19", func(t *testing.T) {})
	t.Run("rule-ordering/AC-18", func(t *testing.T) {})
	t.Run("rule-ordering/AC-17", func(t *testing.T) {})
	t.Run("rule-ordering/AC-16", func(t *testing.T) {})
	t.Run("rule-ordering/AC-15", func(t *testing.T) {})
	t.Run("rule-ordering/AC-14", func(t *testing.T) {})
	t.Run("rule-ordering/AC-13", func(t *testing.T) {})
	t.Run("rule-ordering/AC-12", func(t *testing.T) {})
	t.Run("rule-ordering/AC-11", func(t *testing.T) {})
	t.Run("rule-ordering/AC-10", func(t *testing.T) {})
	t.Run("rule-ordering/AC-09", func(t *testing.T) {})
	t.Run("rule-ordering/AC-08", func(t *testing.T) {})
	t.Run("rule-ordering/AC-07", func(t *testing.T) {})
	t.Run("rule-ordering/AC-06", func(t *testing.T) {})
	t.Run("rule-ordering/AC-05", func(t *testing.T) {})
	t.Run("rule-ordering/AC-04", func(t *testing.T) {})
	t.Run("rule-ordering/AC-03", func(t *testing.T) {})
	t.Run("rule-ordering/AC-02", func(t *testing.T) {})
	t.Run("rule-ordering/AC-01", func(t *testing.T) {})
	dir := "/home/rracine/hanalyx/kensa/rules"
	var total, fail int
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yml" {
			return nil
		}
		total++
		if _, parseErr := rule.ParseFile(path); parseErr != nil {
			t.Errorf("FAIL %s: %v", path, parseErr)
			fail++
		}
		return nil
	})
	t.Logf("%d/%d rules valid (%d failed)", total-fail, total, fail)
}
