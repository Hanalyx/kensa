package auditruleset

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the audit_rule_set handler with the global registry.
func init() {
	handler.Register(New())
}
