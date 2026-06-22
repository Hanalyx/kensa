package kernelio

import (
	"errors"

	"golang.org/x/sys/unix"
)

// fsImmutableFL is the inode immutable flag (FS_IMMUTABLE_FL). A file with
// this flag (chattr +i) cannot be modified, renamed, or removed — so a
// rollback that would rewrite or delete it cannot succeed. The constant is
// stable in the kernel UAPI (linux/fs.h); defined here to avoid depending on
// its presence in a given x/sys/unix version.
const fsImmutableFL = 0x00000010

// IsImmutable reports whether path has the immutable inode flag set
// (chattr +i), read via the FS_IOC_GETFLAGS ioctl. A path that does not
// exist is not immutable (false, nil) — there is nothing to protect. A path
// on a filesystem that does not support the ioctl returns (false, nil): the
// probe is a best-effort restorability check, not a hard requirement.
func IsImmutable(path string) (bool, error) {
	// O_NOFOLLOW: never follow a symlink at the leaf (a captured path whose
	// leaf is a symlink is not the regular file/dir a rollback rewrites).
	// O_NONBLOCK: never block opening a FIFO/device. O_PATH-free because we
	// need the flags ioctl, but we stat-gate to a regular file or directory
	// first so the open cannot have a device-node open side effect.
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	// Only a regular file or directory can be immutable in a way that blocks
	// a rollback rewrite/removal; a symlink, FIFO, socket, or device node is
	// not something the footprint funnel writes, so it is not unrestorable.
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFDIR:
	default:
		return false, nil
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()

	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		// ENOTTY / EOPNOTSUPP: the filesystem does not support inode flags.
		if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) {
			return false, nil
		}
		return false, err
	}
	return flags&fsImmutableFL != 0, nil
}
