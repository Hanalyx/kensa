package auditnl

import (
	"encoding/hex"

	"github.com/Hanalyx/kensa/internal/agent/kernelio"
)

// FakeAuditTransport is an in-memory test double implementing
// AuditTransport. It embeds kernelio.FakeSysctlTransport for the file +
// api.Transport surface and adds an in-memory kernel rule list, so a test
// can exercise a full audit Apply → Capture → Rollback round trip without
// a real netlink socket. Lives in the production package (a normal file)
// so the audit_rule_set handler tests can share it, mirroring
// servicedbus.FakeTransport / kernelio.FakeSysctlTransport.
type FakeAuditTransport struct {
	*kernelio.FakeSysctlTransport
	// Loaded is the in-memory kernel rule list, keyed by hex(wire).
	Loaded map[string][]byte
	// OpenErr, when set, is returned by AuditClient() — set it to
	// ErrAuditUnavailable to exercise the shell fallback.
	OpenErr error
}

// NewFakeAudit returns a FakeAuditTransport with initialized state.
func NewFakeAudit() *FakeAuditTransport {
	return &FakeAuditTransport{
		FakeSysctlTransport: kernelio.NewFakeSysctl(),
		Loaded:              map[string][]byte{},
	}
}

// AuditClient returns an in-memory client over the fake's rule list, or
// OpenErr when set.
func (f *FakeAuditTransport) AuditClient() (AuditClient, error) {
	if f.OpenErr != nil {
		return nil, f.OpenErr
	}
	return &fakeAuditClient{t: f}, nil
}

// LoadedLines is a test helper returning the count of loaded rules.
func (f *FakeAuditTransport) LoadedCount() int { return len(f.Loaded) }

type fakeAuditClient struct{ t *FakeAuditTransport }

func key(wire []byte) string { return hex.EncodeToString(wire) }

func (c *fakeAuditClient) AddRule(wire []byte) error {
	c.t.Loaded[key(wire)] = append([]byte(nil), wire...)
	return nil
}

func (c *fakeAuditClient) DeleteRule(wire []byte) error {
	delete(c.t.Loaded, key(wire))
	return nil
}

func (c *fakeAuditClient) GetRules() ([][]byte, error) {
	out := make([][]byte, 0, len(c.t.Loaded))
	for _, w := range c.t.Loaded {
		out = append(out, w)
	}
	return out, nil
}

func (c *fakeAuditClient) Close() error { return nil }

// Compile-time assertions.
var (
	_ AuditTransport = (*FakeAuditTransport)(nil)
	_ AuditClient    = (*fakeAuditClient)(nil)
)
