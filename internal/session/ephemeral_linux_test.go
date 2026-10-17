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

// A base that cannot be statfs'd is skipped, not fatal, and the search moves on
// to the next candidate. "/nonexistent-..." guarantees isTmpfs is false.
func TestEphemeralDirSkipsUnusableBase(t *testing.T) {
	saved := ephemeralBases
	ephemeralBases = []string{"/nonexistent-agentbox-base-dir"}
	t.Cleanup(func() { ephemeralBases = saved })

	dir, err := ephemeralDir("agentbox-skip-")
	if err != nil {
		t.Fatalf("a skipped base must still yield a directory: %v", err)
	}
	defer os.RemoveAll(dir)
}

// With no usable base at all, the failure must be reported rather than a fake
// success.
func TestEphemeralDirReportsErrorWhenNoTempIsUsable(t *testing.T) {
	saved := ephemeralBases
	ephemeralBases = nil
	t.Cleanup(func() { ephemeralBases = saved })

	// os.MkdirTemp("") falls back to TMPDIR; point it somewhere absent.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if _, err := ephemeralDir("agentbox-none-"); err == nil {
		t.Fatal("expected an error when no temporary directory is usable")
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
