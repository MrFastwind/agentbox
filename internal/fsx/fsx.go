// Package fsx is the filesystem surface that internal/policy needs, behind an
// interface so the security core can be tested against a synthetic host —
// symlink traps, planted credential files, hostile layouts — without touching
// the real filesystem or a container runtime.
package fsx

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// FS is the minimal filesystem surface used by policy.
type FS interface {
	Abs(string) (string, error)
	EvalSymlinks(string) (string, error)
	// Readlink returns a symlink's own target as written, without resolving
	// it. EvalSymlinks answers "where does this end up"; Readlink answers
	// "what did the configuration say". Deciding whether a followed link may
	// be mounted needs both.
	Readlink(string) (string, error)
	Lstat(string) (os.FileInfo, error)
	ReadFile(string) ([]byte, error)
	ReadDir(string) ([]os.DirEntry, error)
	Getwd() (string, error)
	UserHomeDir() (string, error)
}

// Real is the production FS, backed by the os package.
type Real struct{}

func (Real) Abs(p string) (string, error)            { return filepath.Abs(p) }
func (Real) EvalSymlinks(p string) (string, error)   { return filepath.EvalSymlinks(p) }
func (Real) Readlink(p string) (string, error)       { return os.Readlink(p) }
func (Real) Lstat(p string) (os.FileInfo, error)     { return os.Lstat(p) }
func (Real) ReadFile(p string) ([]byte, error)       { return os.ReadFile(p) }
func (Real) ReadDir(p string) ([]os.DirEntry, error) { return os.ReadDir(p) }
func (Real) Getwd() (string, error)                  { return os.Getwd() }
func (Real) UserHomeDir() (string, error)            { return os.UserHomeDir() }

var _ FS = Real{}

// SHA256Hex is used by the audit log to record exactly which bytes were seeded.
func SHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
