package kernelio

import "github.com/Hanalyx/kensa/internal/agent/fsatomic"

// FileTransport is the capability a transport implements when it can do
// atomic file IO on the target host: the fsatomic write/replace/remove
// primitives plus an existence-aware read. The mount_option_set handler
// asserts this for its /etc/fstab edits (its runtime remount stays on
// mount(8) by design — see the kernelio-mount spec). SysctlTransport
// embeds it for the sysctl persist drop-in.
type FileTransport interface {
	fsatomic.Transport
	ReadFileIfExists(path string) (content string, existed bool, err error)
}

// SysctlTransport is the capability interface a transport implements when
// it can apply sysctl changes via direct kernel IO — i.e. the agent-mode
// local transport on the target host. A handler type-asserts
// transport.(kernelio.SysctlTransport); on success it uses the
// procfs/atomic-file path, and on failure (the SSH shell transport does
// not implement it) it falls back to `sysctl -w` + shell file writes.
//
// It embeds FileTransport because the sysctl handler's persistence layer
// (the /etc/sysctl.d drop-in) is an ordinary atomic file write — so one
// assertion yields both the runtime proc ops and the atomic persist ops.
type SysctlTransport interface {
	FileTransport
	WriteSysctl(key, value string) error
	ReadSysctl(key string) (string, error)
}
