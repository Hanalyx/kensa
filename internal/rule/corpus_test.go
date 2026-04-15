package rule_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/Hanalyx/kensa-go/internal/rule"
)

func TestCorpusParity(t *testing.T) {
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
