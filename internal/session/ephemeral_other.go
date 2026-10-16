//go:build !linux

package session

import "os"

// ephemeralDir on non-Linux platforms falls back to the system temporary
// directory. agentbox targets rootless podman on Linux; this exists so
// the package still builds elsewhere.
func ephemeralDir(pattern string) (string, error) {
	dir, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", err
	}
	_ = os.Chmod(dir, 0o700)
	return dir, nil
}
