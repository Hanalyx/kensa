package main

import (
	"fmt"

	"github.com/Hanalyx/kensa/internal/varsub"
)

// introspectionVars resolves the variables the corpus-wide read models load
// rules with: `kensa list frameworks`, the generic `kensa coverage --framework`
// path, and `kensa info`.
//
// These commands describe the corpus, not a host. They take no host, no
// --config-dir and no --var, so the only tier that can apply is the built-in
// floor Kensa ships inside the binary. Passing nil instead drops every rule
// carrying a `{{ name }}` template, which silently lowered every published
// framework count.
//
// Only the embedded tier is resolved, deliberately. Reading an operator's
// configuration here would make a corpus description depend on the machine it
// ran on, so the same corpus would answer differently to two people. The scan
// path keeps the full tier chain, because there the host is known and operator
// values are the point.
func introspectionVars() (varsub.Variables, error) {
	vars, err := varsub.ResolveTiers("", "", nil, nil)
	if err != nil {
		// Never fall back to nil: that is the defect this function exists to
		// close, and it would fail by quietly reporting a short corpus rather
		// than by stopping.
		return nil, fmt.Errorf("resolve built-in variable defaults: %w", err)
	}
	return vars, nil
}
