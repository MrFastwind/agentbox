package update

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func writeStateFile(t *testing.T, dir, content string) error {
	t.Helper()
	return os.WriteFile(filepath.Join(dir, stateFile), []byte(content), 0o600)
}

func testStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AGENTBOX_STATE_DIR", dir)
	return dir
}

func TestLoadStateMissingReturnsEmptyState(t *testing.T) {
	testStateDir(t)
	state, err := LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Agents) != 0 || len(state.History) != 0 {
		t.Fatal("missing state was not empty")
	}
	if state.Version != 2 {
		t.Fatalf("state version = %d", state.Version)
	}
}

func TestLoadStateReportsLegacyState(t *testing.T) {
	dir := testStateDir(t)
	if err := writeStateFile(t, dir, "version: 1\nagents: {}\n"); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState()
	if !errors.Is(err, ErrLegacyState) || state != nil {
		t.Fatalf("LoadState = (%+v, %v)", state, err)
	}
	if fresh := NewState(); fresh.Version != 2 || len(fresh.Agents) != 0 {
		t.Fatalf("NewState = %+v", fresh)
	}
}

func TestSaveAndLoadState(t *testing.T) {
	dir := testStateDir(t)
	state, err := LoadState()
	if err != nil {
		t.Fatal(err)
	}
	pin := AgentPin{Version: "2.4.1", Args: map[string]string{"OPENCODE_VERSION": "2.4.1"}, Source: "test"}
	if err := state.Set("opencode", RecordFor("opencode", pin, ImageRef("opencode", pin.Version))); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(state); err != nil {
		t.Fatal(err)
	}
	if _, err := filepath.Abs(filepath.Join(dir, stateFile)); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := loaded.For("opencode")
	if !ok || rec.Version != "2.4.1" || rec.Image != "localhost/agentbox/opencode:2.4.1" {
		t.Fatalf("loaded record = %+v, ok=%v", rec, ok)
	}
	if !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`).MatchString(rec.UpdatedAt) {
		t.Fatalf("UpdatedAt = %q", rec.UpdatedAt)
	}
}

func TestStateRecordsHistoryAndReturnsCopies(t *testing.T) {
	testStateDir(t)
	state, _ := LoadState()
	old := AgentPin{Version: "1.5.9", Args: map[string]string{"AGY_VERSION": "1.5.9"}}
	next := AgentPin{Version: "1.5.16", Args: map[string]string{"AGY_VERSION": "1.5.16"}}
	if err := state.Set("antigravity", RecordFor("antigravity", old, ImageRef("antigravity", old.Version))); err != nil {
		t.Fatal(err)
	}
	if err := state.Set("antigravity", RecordFor("antigravity", next, ImageRef("antigravity", next.Version))); err != nil {
		t.Fatal(err)
	}
	rec, ok := state.Historical("antigravity", "1.5.9")
	if !ok || rec.Args["AGY_VERSION"] != "1.5.9" {
		t.Fatalf("history record = %+v, ok=%v", rec, ok)
	}
	rec.Args["AGY_VERSION"] = "tampered"
	again, _ := state.Historical("antigravity", "1.5.9")
	if again.Args["AGY_VERSION"] != "1.5.9" {
		t.Fatal("Historical aliased the stored args")
	}
	if _, ok := state.Historical("antigravity", "9.9.9"); ok {
		t.Fatal("Historical returned an unknown version")
	}
	current, _ := state.For("antigravity")
	current.Args["AGY_VERSION"] = "tampered"
	againCurrent, _ := state.For("antigravity")
	if againCurrent.Args["AGY_VERSION"] != "1.5.16" {
		t.Fatal("For aliased the stored args")
	}
	if _, ok := state.For("unknown"); ok {
		t.Fatal("For returned an unknown agent")
	}
}

func TestStateSetRejectsInvalidRecords(t *testing.T) {
	testStateDir(t)
	state, _ := LoadState()
	for _, tc := range []struct {
		name string
		rec  Record
	}{
		{"bad version", Record{Version: "latest", Image: ImageRef("pi", "1.5.2")}},
		{"bad image", Record{Version: "1.5.2", Image: "pi:latest"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := state.Set("pi", tc.rec); err == nil {
				t.Fatal("Set accepted an invalid record")
			}
		})
	}
	if err := SaveState(nil); err == nil {
		t.Fatal("SaveState accepted a nil state")
	}
}

func TestLoadStateRejectsMalformedFiles(t *testing.T) {
	dir := testStateDir(t)
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"future version", "version: 3\n"},
		{"unknown field", "version: 2\nunexpected: true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := writeStateFile(t, dir, tc.content); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadState(); err == nil {
				t.Fatal("LoadState accepted a malformed file")
			}
		})
	}
}

func TestImageRefsAreFullyQualified(t *testing.T) {
	if got := ImageRef("pi", "1.6.0"); got != "localhost/agentbox/pi:1.6.0" {
		t.Fatalf("ImageRef = %q", got)
	}
	if got := LatestRef("pi"); got != "localhost/agentbox/pi:latest" {
		t.Fatalf("LatestRef = %q", got)
	}
}

func TestStatePathUsesXDGAndOverride(t *testing.T) {
	t.Setenv("AGENTBOX_STATE_DIR", "")
	t.Setenv("XDG_STATE_HOME", "/xdg")
	path, err := StatePath()
	if err != nil || path != filepath.Join("/xdg", "agentbox", stateFile) {
		t.Fatalf("StatePath = (%q, %v)", path, err)
	}
	t.Setenv("AGENTBOX_STATE_DIR", "/override")
	path, err = StatePath()
	if err != nil || path != filepath.Join("/override", stateFile) {
		t.Fatalf("StatePath override = (%q, %v)", path, err)
	}
}
