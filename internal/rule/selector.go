package rule

import (
	"fmt"

	"github.com/Hanalyx/kensa/api"
)

// Select returns the best [api.Implementation] for rule given caps.
//
// Evaluation is top-to-bottom per the V1 schema spec (§3.5.1):
//
//  1. Implementations with a `when` gate are evaluated in order. The first
//     whose gate is satisfied by caps is returned.
//  2. If no gated implementation matched, the `default: true` implementation
//     is returned as the fallback.
//
// An error is returned only when the rule has no default implementation or
// when a `when` expression is structurally invalid.
func Select(rule *api.Rule, caps api.CapabilitySet) (*api.Implementation, error) {
	if caps == nil {
		caps = api.CapabilitySet{}
	}

	var defImpl *api.Implementation
	for i := range rule.Implementations {
		impl := &rule.Implementations[i]
		if impl.Default {
			if defImpl == nil {
				defImpl = impl
			}
			continue // default is the fallback, evaluated last
		}
		if impl.When == nil {
			// Ungated non-default: always matches, acts like first in list.
			return impl, nil
		}
		ok, err := evalWhen(impl.When, caps)
		if err != nil {
			return nil, fmt.Errorf("rule %s impl %d: when: %w", rule.ID, i, err)
		}
		if ok {
			return impl, nil
		}
	}

	if defImpl != nil {
		return defImpl, nil
	}
	return nil, fmt.Errorf("rule %s: no implementation matched and no default", rule.ID)
}

// evalWhen evaluates a when expression against caps and returns true when
// the condition is satisfied.
//
// Supported shapes:
//
//	string                    → single capability name (true when caps[name] is true)
//	{all: [cap, ...]}         → all listed capabilities must be true
//	{any: [cap, ...]}         → at least one listed capability must be true
//	{not: cap}                → the named capability must be false
func evalWhen(when interface{}, caps api.CapabilitySet) (bool, error) {
	if when == nil {
		return true, nil
	}

	switch v := when.(type) {
	case string:
		return caps[v], nil

	case map[string]interface{}:
		if all, ok := v["all"]; ok {
			return evalAll(all, caps)
		}
		if any, ok := v["any"]; ok {
			return evalAny(any, caps)
		}
		if not, ok := v["not"]; ok {
			return evalNot(not, caps)
		}
		return false, fmt.Errorf("unknown when expression keys: %v", v)

	default:
		return false, fmt.Errorf("unsupported when type %T (expected string or map)", when)
	}
}

// evalAll returns true when every item in items is a satisfied capability.
func evalAll(items interface{}, caps api.CapabilitySet) (bool, error) {
	list, err := toStringList(items)
	if err != nil {
		return false, fmt.Errorf("all: %w", err)
	}
	for _, cap := range list {
		if !caps[cap] {
			return false, nil
		}
	}
	return true, nil
}

// evalAny returns true when at least one item in items is a satisfied capability.
func evalAny(items interface{}, caps api.CapabilitySet) (bool, error) {
	list, err := toStringList(items)
	if err != nil {
		return false, fmt.Errorf("any: %w", err)
	}
	for _, cap := range list {
		if caps[cap] {
			return true, nil
		}
	}
	return false, nil
}

// evalNot returns true when the named capability is false.
func evalNot(item interface{}, caps api.CapabilitySet) (bool, error) {
	name, ok := item.(string)
	if !ok {
		return false, fmt.Errorf("not: expected string, got %T", item)
	}
	return !caps[name], nil
}

// toStringList coerces items (expected []interface{} from YAML decoding) into
// a []string.
func toStringList(items interface{}) ([]string, error) {
	raw, ok := items.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected list, got %T", items)
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		s, ok := r.(string)
		if !ok {
			return nil, fmt.Errorf("expected string element, got %T (%v)", r, r)
		}
		out = append(out, s)
	}
	return out, nil
}
