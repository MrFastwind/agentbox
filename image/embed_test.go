package image

import (
	"io/fs"
	"os"
	"testing"

	"agentbox/internal/agent"
)

// The embedded set is what the shipped binary can build. A target that is
// registered but not embedded would only fail at `images build` time, on a
// machine that no longer has the source tree.
func TestEmbeddedInputsCoverEveryImageTarget(t *testing.T) {
	reg := agent.New("/home/agent")
	for _, name := range reg.Names() {
		if name == "shell" {
			// The bare sandbox IS the base image; there is nothing extra to build.
			continue
		}
		if _, err := FS.ReadFile("Containerfile." + name); err != nil {
			t.Errorf("no embedded Containerfile for agent %q: %v", name, err)
		}
	}
	for _, target := range []string{"base", "opencode", "pi", "claude", "antigravity"} {
		if _, err := FS.ReadFile("Containerfile." + target); err != nil {
			t.Errorf("no embedded Containerfile for %q: %v", target, err)
		}
	}
	if _, err := FS.ReadFile("entrypoint.sh"); err != nil {
		t.Errorf("no embedded entrypoint.sh: %v", err)
	}
}

// The embedded bytes must be the bytes the pin tests audit. If they ever
// diverge — a stale copy, a moved file — the tests would keep passing while the
// binary shipped different build inputs.
func TestEmbeddedInputsMatchDisk(t *testing.T) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("embedded image inputs are empty")
	}
	for _, e := range entries {
		embedded, err := FS.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("reading embedded %s: %v", e.Name(), err)
		}
		onDisk, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("reading %s from the source tree: %v", e.Name(), err)
		}
		if string(embedded) != string(onDisk) {
			t.Errorf("%s: embedded copy differs from the file in image/", e.Name())
		}
	}
}

// Only the build inputs are embedded. A test file or editor backup must not
// ride along, since the build context ships to podman verbatim.
func TestEmbeddedSetIsExactlyTheBuildInputs(t *testing.T) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"Containerfile.base":        true,
		"Containerfile.opencode":    true,
		"Containerfile.pi":          true,
		"Containerfile.claude":      true,
		"Containerfile.antigravity": true,
		"entrypoint.sh":             true,
	}
	for _, e := range entries {
		if !want[e.Name()] {
			t.Errorf("unexpected embedded input %q", e.Name())
		}
		delete(want, e.Name())
	}
	for name := range want {
		t.Errorf("missing embedded input %q", name)
	}
}
