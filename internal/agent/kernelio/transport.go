package kernelio

import "github.com/Hanalyx/kensa/internal/agent/fsatomic"

// SysctlTransport is the capability interface a transport implements
// when it can apply sysctl changes via direct kernel IO — i.e. the
// agent-mode local transport on the target host. A handler type-asserts
// transport.(kernelio.SysctlTransport); on success it uses the
// procfs/atomic-file path, and on failure (the SSH shell transport does
// not implement it) it falls back to `sysctl -w` + shell file writes.
//
// It embeds fsatomic.Transport because the sysctl handler's persistence
// layer (the /etc/sysctl.d drop-in) is an ordinary atomic file write —
// so one assertion yields both the runtime proc ops and the atomic
// persist ops, and a transport that offers one offers the other (the
// local transport implements both).
type SysctlTransport interface {
	fsatomic.Transport
	WriteSysctl(key, value string) error
	ReadSysctl(key string) (string, error)
	ReadFileIfExists(path string) (content string, existed bool, err error)
}
