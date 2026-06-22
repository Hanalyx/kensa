package footprint

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/internal/agent/auditnl"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/agent/systemd"
)

// systemdStub is a trivial systemd.Transport that records the last op so the
// test can prove the Recorder forwarded to it.
type systemdStub struct{ lastOp string }

func (s *systemdStub) reply(op string) (*systemd.Response, error) {
	s.lastOp = op
	return &systemd.Response{Success: true, Op: op}, nil
}
func (s *systemdStub) Enable(context.Context, string) (*systemd.Response, error) {
	return s.reply("enable")
}
func (s *systemdStub) Disable(context.Context, string) (*systemd.Response, error) {
	return s.reply("disable")
}
func (s *systemdStub) Mask(context.Context, string) (*systemd.Response, error) {
	return s.reply("mask")
}
func (s *systemdStub) Unmask(context.Context, string) (*systemd.Response, error) {
	return s.reply("unmask")
}
func (s *systemdStub) Start(context.Context, string) (*systemd.Response, error) {
	return s.reply("start")
}
func (s *systemdStub) Stop(context.Context, string) (*systemd.Response, error) {
	return s.reply("stop")
}
func (s *systemdStub) UnitState(context.Context, string) (*systemd.Response, error) {
	return s.reply("state")
}

// fullCapFake offers every capability the agent transport does: file + sysctl
// + audit (via the auditnl fake, which embeds the kernelio fake and so also
// provides api.Transport) and systemd (via the stub).
type fullCapFake struct {
	*auditnl.FakeAuditTransport
	*systemdStub
}

// The Recorder must forward systemd.Transport and auditnl.AuditTransport so a
// handler's capability assertion still selects the agent path when the
// transport is wrapped — omitting either silently routes the handler to its
// shell fallback (the regression this guards against).
//
// @spec footprint-funnel
// @ac AC-06
func TestRecorder_ForwardsSystemdAndAudit(t *testing.T) {
	t.Run("footprint-funnel/AC-06", func(t *testing.T) {})

	inner := &fullCapFake{FakeAuditTransport: auditnl.NewFakeAudit(), systemdStub: &systemdStub{}}
	rec := NewRecorder(inner)

	// systemd.Transport assertion must succeed on the wrapped transport.
	st, ok := interface{}(rec).(systemd.Transport)
	if !ok {
		t.Fatal("Recorder does not satisfy systemd.Transport — service handlers would drop to systemctl")
	}
	resp, err := st.Disable(context.Background(), "telnet.socket")
	if err != nil || resp == nil || !resp.Success {
		t.Fatalf("Disable forward: resp=%+v err=%v", resp, err)
	}
	if inner.lastOp != "disable" {
		t.Errorf("systemd call not forwarded to inner: lastOp=%q", inner.lastOp)
	}

	// auditnl.AuditTransport assertion must succeed, and the client must be
	// the inner's (an AddRule lands in the inner fake's loaded set).
	at, ok := interface{}(rec).(auditnl.AuditTransport)
	if !ok {
		t.Fatal("Recorder does not satisfy auditnl.AuditTransport — audit_rule_set would drop to augenrules")
	}
	c, err := at.AuditClient()
	if err != nil {
		t.Fatalf("AuditClient forward: %v", err)
	}
	defer c.Close()
	if err := c.AddRule([]byte{0x01, 0x02}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if inner.LoadedCount() != 1 {
		t.Errorf("audit client not forwarded to inner: loaded=%d", inner.LoadedCount())
	}

	// Neither forward is a filesystem mutation — nothing recorded.
	if rec.Footprint().Len() != 0 {
		t.Errorf("systemd/audit forwards must not record a footprint entry; got %v", rec.Footprint().Entries())
	}
}

// When the wrapped transport lacks a capability (the defensive non-agent
// case), the forward returns a sentinel rather than panicking.
//
// @spec footprint-funnel
// @ac AC-06
func TestRecorder_MissingCapabilityForwards(t *testing.T) {
	t.Run("footprint-funnel/AC-06", func(t *testing.T) {})

	rec := NewRecorder(kernelio.NewFakeSysctl()) // no systemd, no audit
	if _, err := rec.Enable(context.Background(), "x"); err != errNoCapability {
		t.Errorf("Enable without capability: want errNoCapability, got %v", err)
	}
	if _, err := rec.AuditClient(); err != auditnl.ErrAuditUnavailable {
		t.Errorf("AuditClient without capability: want ErrAuditUnavailable, got %v", err)
	}
}
