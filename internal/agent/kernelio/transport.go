package kernelio

import (
	"io/fs"

	"github.com/Hanalyx/kensa/internal/agent/fsatomic"
)

// FileTransport is the capability a transport implements when it can do
// atomic file IO on the target host: the fsatomic write/replace/remove
// primitives, an existence-aware read, and a mkdir-all. The
// mount_option_set handler asserts this for its /etc/fstab edits (its
// runtime remount stays on mount(8) by design — see the kernelio-mount
// spec); dconf_set asserts it for its /etc/dconf drop-in writes.
// SysctlTransport embeds it for the sysctl persist drop-in.
type FileTransport interface {
	fsatomic.Transport
	ReadFileIfExists(path string) (content string, existed bool, err error)
	MkdirAll(path string, mode fs.FileMode) error
}

// ModuleTransport is the capability a transport implements when it can
// manage kernel modules via direct kernel IO: the FileTransport ops for
// the /etc/modprobe.d blacklist drop-in, plus DeleteModule (the
// delete_module(2) runtime unload). The kernel_module_disable handler
// asserts it and falls back to the modprobe + shell file-write path
// otherwise.
type ModuleTransport interface {
	FileTransport
	DeleteModule(name string) error
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
