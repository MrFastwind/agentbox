//go:build linux

package session

import (
	"os"
	"syscall"
)

// tmpfsMagic is TMPFS_MAGIC from statfs(2).
const tmpfsMagic = 0x01021994

// ephemeralBases are the tmpfs candidates, in preference order. It is a
// variable so a test can force the non-tmpfs fallback path.
var ephemeralBases = []string{"/dev/shm", os.TempDir()}

// ephemeralDir returns a fresh 0700 directory, preferring a tmpfs so that agent
// state never reaches disk while it is live.
//
// This is not merely tidiness. A podman --tmpfs is created owned by container 0
// and podman rejects uid=/gid= on it, so under keep-id the sandbox user cannot
// write to it. A directory that this process creates is owned by the invoking
// user, which is exactly who the keep-id user maps to.
func ephemeralDir(pattern string) (string, error) {
	for _, base := range ephemeralBases {
		if !isTmpfs(base) {
			continue
		}
		if dir, err := os.MkdirTemp(base, pattern); err == nil {
			_ = os.Chmod(dir, 0o700)
			return dir, nil
		}
	}

	dir, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", err
	}
	_ = os.Chmod(dir, 0o700)
	return dir, nil
}

func isTmpfs(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	return st.Type == tmpfsMagic
}
