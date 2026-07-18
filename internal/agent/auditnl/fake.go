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
	// DeleteNoop, when true, makes DeleteRule return nil WITHOUT removing
	// the rule — modeling a kernel that accepts the call but leaves the
	// rule loaded, so the rollback read-back verify can be exercised.
	DeleteNoop bool
	// DeleteErr, when set, is returned by DeleteRule — modeling a kernel
	// that rejects the unload (e.g. EPERM on an immutable config).
	DeleteErr error
	// Enabled models `auditctl -s` enabled: 0=disabled, 1=enabled(mutable),
	// 2=immutable. GetStatus() returns it. Set 2 to exercise the staged
	// (reboot-deferred) path where the handler must NOT attempt a load.
	Enabled int
	// AddErr, when set, is returned by AddRule — modeling a kernel that
	// rejects the load (e.g. EPERM on an immutable config that a caller
	// reached without a GetStatus pre-check).
	AddErr error
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
	if c.t.AddErr != nil {
		return c.t.AddErr // kernel rejected the load (e.g. EPERM on immutable)
	}
	c.t.Loaded[key(wire)] = append([]byte(nil), wire...)
	return nil
}

func (c *fakeAuditClient) DeleteRule(wire []byte) error {
	if c.t.DeleteErr != nil {
		return c.t.DeleteErr // kernel rejected the unload (e.g. EPERM)
	}
	if c.t.DeleteNoop {
		return nil // accepted but not removed (immutable-kernel model)
	}
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

func (c *fakeAuditClient) GetStatus() (int, error) { return c.t.Enabled, nil }

func (c *fakeAuditClient) Close() error { return nil }

// Compile-time assertions.
var (
	_ AuditTransport = (*FakeAuditTransport)(nil)
	_ AuditClient    = (*fakeAuditClient)(nil)
)
