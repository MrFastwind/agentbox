//go:build linux

package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEphemeralDirIsPrivateAndNamed(t *testing.T) {
	dir, err := ephemeralDir("agentbox-test-")
	if err != nil {
		t.Fatalf("ephemeralDir: %v", err)
	}
	defer os.RemoveAll(dir)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("returned directory does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("ephemeralDir returned a non-directory: %s", dir)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("ephemeral dir mode = %o, want 0700", got)
	}
	if !strings.HasPrefix(filepath.Base(dir), "agentbox-test-") {
		t.Fatalf("ephemeral dir does not carry the requested prefix: %s", dir)
	}
}

// When no candidate base is a tmpfs, the function must still return a usable
// private directory rather than failing.
func TestEphemeralDirFallsBackWhenNoTmpfs(t *testing.T) {
	saved := ephemeralBases
	ephemeralBases = []string{t.TempDir()} // deliberately not a tmpfs
	t.Cleanup(func() { ephemeralBases = saved })

	dir, err := ephemeralDir("agentbox-fallback-")
	if err != nil {
		t.Fatalf("ephemeralDir: %v", err)
	}
	defer os.RemoveAll(dir)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("fallback dir mode = %o, want 0700", got)
	}
}

// A tmpfs base that cannot be written to must be skipped, not fatal: the state
// directory is required for the sandbox to run at all.
func TestEphemeralDirSkipsUnwritableTmpfs(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	base, err := os.MkdirTemp("/dev/shm", "agentbox-ro-")
	if err != nil {
		t.Skipf("no /dev/shm: %v", err)
	}
	defer func() {
		_ = os.Chmod(base, 0o700)
		_ = os.RemoveAll(base)
	}()
	if !isTmpfs(base) {
		t.Skip("/dev/shm is not a tmpfs here")
	}
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatal(err)
	}

	saved := ephemeralBases
	ephemeralBases = []string{base}
	t.Cleanup(func() { ephemeralBases = saved })

	dir, err := ephemeralDir("agentbox-unwritable-")
	if err != nil {
		t.Fatalf("expected a fallback, got error: %v", err)
	}
	defer os.RemoveAll(dir)
	if filepath.Dir(dir) == base {
		t.Fatal("directory was created in the unwritable base")
	}
}

func TestIsTmpfsRejectsMissingPath(t *testing.T) {
	if isTmpfs("/nonexistent/agentbox/definitely-missing") {
		t.Fatal("a path that cannot be statfs'd must not be reported as tmpfs")
	}
}
