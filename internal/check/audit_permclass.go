package check

// auditPermClass lists, for each arch and perm value, the syscalls auditctl
// selects for a path= or dir= rule that names that arch and perm and no -S.
// auditctl -l prints that list where the rule had none. The kernel's perm
// filter only fires on these syscalls, so a loaded rule audits every event
// the rule does when its syscall set contains one whole list (C-07).
//
// Each entry holds one list per captured audit userspace version whose list
// differs; a loaded set must contain at least one of them. Built only from
// captured auditctl -l output, never from source reading:
//   - audit-4.0.3 (RHEL 10.2, kernel 6.12): every entry;
//   - audit-3.1.5 (Rocky 9.8, kernel 5.14): "wa" only, where its list is the
//     same set as 4.0.3's for both arches, so it adds no second list.
//
// A version or perm value not captured can only fail the comparison.
var auditPermClass = map[string]map[string][][]string{
	"b32": {
		"r":    {{"open", "readlink", "quotactl", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "openat", "readlinkat", "openat2"}},
		"w":    {{"open", "creat", "link", "unlink", "mknod", "rename", "mkdir", "rmdir", "acct", "symlink", "swapon", "truncate", "ftruncate", "quotactl", "openat", "mkdirat", "mknodat", "unlinkat", "renameat", "linkat", "symlinkat", "fallocate", "renameat2", "bind", "openat2"}},
		"x":    {{"execve"}},
		"a":    {{"link", "chmod", "lchown", "fchmod", "fchown", "chown", "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr", "fchownat", "linkat", "fchmodat"}},
		"wa":   {{"open", "creat", "link", "unlink", "mknod", "chmod", "lchown", "rename", "mkdir", "rmdir", "acct", "symlink", "swapon", "truncate", "ftruncate", "fchmod", "fchown", "quotactl", "chown", "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr", "openat", "mkdirat", "mknodat", "fchownat", "unlinkat", "renameat", "linkat", "symlinkat", "fchmodat", "fallocate", "renameat2", "bind", "openat2"}},
		"rwa":  {{"open", "creat", "link", "unlink", "mknod", "chmod", "lchown", "rename", "mkdir", "rmdir", "acct", "symlink", "readlink", "swapon", "truncate", "ftruncate", "fchmod", "fchown", "quotactl", "chown", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "openat", "mkdirat", "mknodat", "fchownat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "fallocate", "renameat2", "bind", "openat2"}},
		"rwxa": {{"open", "creat", "link", "unlink", "execve", "mknod", "chmod", "lchown", "rename", "mkdir", "rmdir", "acct", "symlink", "readlink", "swapon", "truncate", "ftruncate", "fchmod", "fchown", "quotactl", "chown", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "openat", "mkdirat", "mknodat", "fchownat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "fallocate", "renameat2", "bind", "openat2"}},
	},
	"b64": {
		"r":    {{"open", "readlink", "quotactl", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "openat", "readlinkat", "openat2"}},
		"w":    {{"open", "bind", "truncate", "ftruncate", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "mknod", "acct", "swapon", "quotactl", "openat", "mkdirat", "mknodat", "unlinkat", "renameat", "linkat", "symlinkat", "fallocate", "renameat2", "openat2"}},
		"x":    {{"execve"}},
		"a":    {{"link", "chmod", "fchmod", "chown", "fchown", "lchown", "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr", "fchownat", "linkat", "fchmodat"}},
		"wa":   {{"open", "bind", "truncate", "ftruncate", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "chmod", "fchmod", "chown", "fchown", "lchown", "mknod", "acct", "swapon", "quotactl", "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr", "openat", "mkdirat", "mknodat", "fchownat", "unlinkat", "renameat", "linkat", "symlinkat", "fchmodat", "fallocate", "renameat2", "openat2"}},
		"rwa":  {{"open", "bind", "truncate", "ftruncate", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "mknod", "acct", "swapon", "quotactl", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "openat", "mkdirat", "mknodat", "fchownat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "fallocate", "renameat2", "openat2"}},
		"rwxa": {{"open", "bind", "execve", "truncate", "ftruncate", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "mknod", "acct", "swapon", "quotactl", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "openat", "mkdirat", "mknodat", "fchownat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "fallocate", "renameat2", "openat2"}},
	},
}
