package cmd

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/agent"
	"agentbox/internal/cli"
	"agentbox/internal/policy"
	"agentbox/internal/session"
	"agentbox/internal/update"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func updateTestResolver(t *testing.T) {
	t.Helper()
	saved := newUpdateResolver
	t.Cleanup(func() { newUpdateResolver = saved })
	integrity := "sha512-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 64)))
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := ""
		switch {
		case strings.Contains(r.URL.Path, "/repos/anomalyco/opencode/releases"):
			body = `[{"tag_name":"v2.4.1","assets":[{"name":"opencode-linux-x64-musl.tar.gz","digest":"sha256:` + strings.Repeat("1", 64) + `"},{"name":"opencode-linux-arm64-musl.tar.gz","digest":"sha256:` + strings.Repeat("2", 64) + `"}]}]`
		case strings.Contains(r.URL.Path, "/repos/anthropics/claude-code/releases"):
			body = `[{"tag_name":"v2.1.331","assets":[{"name":"claude-linux-x64-musl.tar.gz","digest":"sha256:` + strings.Repeat("3", 64) + `"},{"name":"claude-linux-arm64-musl.tar.gz","digest":"sha256:` + strings.Repeat("4", 64) + `"}]}]`
		case strings.Contains(r.URL.Path, "/repos/google-antigravity/antigravity-cli/releases"):
			body = `[{"tag_name":"1.5.16","assets":[{"name":"agy_cli_linux_x64_musl.tar.gz","digest":"sha256:` + strings.Repeat("5", 64) + `"},{"name":"agy_cli_linux_arm64_musl.tar.gz","digest":"sha256:` + strings.Repeat("6", 64) + `"}]}]`
		case strings.Contains(r.URL.EscapedPath(), "pi-coding-agent"):
			body = `{"dist-tags":{"latest":"1.6.0"},"versions":{"1.6.0":{"dist":{"integrity":"` + integrity + `"},"engines":{"node":">=22.19.0"}}}}`
		default:
			return nil, fmt.Errorf("unexpected request %s", r.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}
	newUpdateResolver = func() *update.Resolver {
		return &update.Resolver{
			Client:      client,
			GitHubAPI:   "http://gh.test",
			NPMRegistry: "http://npm.test",
			Now:         func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) },
		}
	}
}

func seedInstalledState(t *testing.T, versions map[string]string) {
	t.Helper()
	pins, err := loadPins()
	if err != nil {
		t.Fatal(err)
	}
	state, err := update.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	for name, version := range versions {
		pin := pins.Agents[name]
		pin.Version = version
		pin.Args[name+"_VERSION"] = version
		if err := state.Set(name, update.RecordFor(name, pin, update.ImageRef(name, version))); err != nil {
			t.Fatal(err)
		}
	}
	if err := update.SaveState(state); err != nil {
		t.Fatal(err)
	}
}

func TestImagesUpdateRecoversLegacyState(t *testing.T) {
	writeContainerFilesHelper(t)
	dir := t.TempDir()
	t.Setenv("AGENTBOX_STATE_DIR", dir)
	updateTestResolver(t)
	legacy := "version: 1\nagents:\n  opencode:\n    version: 1.19.5\n    image: localhost/agentbox/opencode:1.19.5\n"
	if err := os.WriteFile(filepath.Join(dir, "images.yaml"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errb := capture(t, func() int { return runImages([]string{"check", "--agent", "opencode"}) })
	if code != 0 || !strings.Contains(out, "installed=1.19.5 (embedded, not installed)") {
		t.Fatalf("check = (%d, %q, %q)", code, out, errb)
	}

	code, out, errb = capture(t, func() int { return runImages([]string{"update", "--dry-run", "--agent", "opencode"}) })
	if code != 0 || !strings.Contains(out, "would install opencode 2.4.1") {
		t.Fatalf("update = (%d, %q, %q)", code, out, errb)
	}
}

func TestImagesCheckAndUpdateUsage(t *testing.T) {
	writeContainerFilesHelper(t)
	t.Setenv("AGENTBOX_STATE_DIR", t.TempDir())
	updateTestResolver(t)

	t.Run("Check", func(t *testing.T) {
		code, out, errb := capture(t, func() int { return runImages([]string{"check"}) })
		if code != 0 || errb != "" {
			t.Fatalf("check = (%d, %q)", code, errb)
		}
		for _, want := range []string{"opencode: embedded=", "pi: embedded=", "claude: embedded=", "antigravity: embedded=", "available=2.4.1"} {
			if !strings.Contains(out, want) {
				t.Errorf("check output missing %q: %s", want, out)
			}
		}
	})

	t.Run("DryRun", func(t *testing.T) {
		stubExec(t, func(string, ...string) *exec.Cmd {
			t.Fatal("dry run invoked podman")
			return nil
		})
		code, out, errb := capture(t, func() int { return runImages([]string{"update", "--dry-run"}) })
		if code != 0 || errb != "" {
			t.Fatalf("dry run = (%d, %q)", code, errb)
		}
		if !strings.Contains(out, "would install opencode 2.4.1 as localhost/agentbox/opencode:2.4.1") {
			t.Fatalf("dry run output = %q", out)
		}
	})

	for _, args := range [][]string{nil, {"nope"}, {"check", "--agent"}, {"update", "--agent", "nope"}, {"rollback", "pi"}, {"rollback", "pi", "latest"}} {
		t.Run(fmt.Sprintf("usage_%v", args), func(t *testing.T) {
			code, _, _ := capture(t, func() int { return runImages(args) })
			if code != 2 {
				t.Fatalf("runImages(%v) = %d, want 2", args, code)
			}
		})
	}
}

func TestImagesUpdateBuildsPinnedTagsAndRollback(t *testing.T) {
	writeContainerFilesHelper(t)
	t.Setenv("AGENTBOX_STATE_DIR", t.TempDir())
	updateTestResolver(t)
	seedInstalledState(t, map[string]string{
		"opencode":    "1.19.5",
		"pi":          "1.5.2",
		"claude":      "2.1.325",
		"antigravity": "1.5.9",
	})

	var commands []string
	stubExec(t, func(name string, arg ...string) *exec.Cmd {
		joined := strings.Join(arg, " ")
		commands = append(commands, joined)
		if strings.HasPrefix(joined, "image exists") {
			if strings.Contains(joined, "localhost/agentbox/base:latest") {
				return exec.Command("sh", "-c", "exit 0")
			}
			return exec.Command("sh", "-c", "exit 1")
		}
		return exec.Command("sh", "-c", "exit 0")
	})

	code, out, errb := capture(t, func() int { return runImages([]string{"update"}) })
	if code != 0 || strings.Contains(errb, "agentbox: refusing") {
		t.Fatalf("update = (%d, %q)", code, errb)
	}
	if !strings.Contains(out, "installed antigravity 1.5.16 as localhost/agentbox/antigravity:1.5.16") {
		t.Fatalf("update output = %q", out)
	}
	for _, want := range []string{
		"-t localhost/agentbox/base:latest",
		"-t localhost/agentbox/opencode:2.4.1",
		"-t localhost/agentbox/pi:1.6.0",
		"-t localhost/agentbox/claude:2.1.331",
		"-t localhost/agentbox/antigravity:1.5.16",
		"--build-arg OPENCODE_SHA256_X64=" + strings.Repeat("1", 64),
	} {
		if !strings.Contains(strings.Join(commands, "\n"), want) {
			t.Errorf("podman commands missing %q", want)
		}
	}

	state, err := update.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	for name, version := range map[string]string{"opencode": "2.4.1", "pi": "1.6.0", "claude": "2.1.331", "antigravity": "1.5.16"} {
		rec, ok := state.For(name)
		if !ok || rec.Version != version || rec.Image != update.ImageRef(name, version) {
			t.Errorf("state[%s] = %+v, ok=%v", name, rec, ok)
		}
	}

	code, out, errb = capture(t, func() int { return runImages([]string{"rollback", "opencode", "1.19.5"}) })
	if code != 0 || strings.Contains(errb, "agentbox: refusing") {
		t.Fatalf("rollback = (%d, %q)", code, errb)
	}
	if !strings.Contains(out, "rolled back opencode to 1.19.5") {
		t.Fatalf("rollback output = %q", out)
	}
	if !strings.Contains(strings.Join(commands, "\n"), "tag localhost/agentbox/opencode:1.19.5 localhost/agentbox/opencode:latest") {
		t.Fatal("rollback did not retag latest")
	}
	state, err = update.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := state.For("opencode")
	if !ok || rec.Version != "1.19.5" {
		t.Fatalf("rollback state = %+v, ok=%v", rec, ok)
	}
}

func TestImagesUpdateSkipsCurrentAgents(t *testing.T) {
	writeContainerFilesHelper(t)
	t.Setenv("AGENTBOX_STATE_DIR", t.TempDir())
	updateTestResolver(t)
	seedInstalledState(t, map[string]string{
		"opencode":    "2.4.1",
		"pi":          "1.6.0",
		"claude":      "2.1.331",
		"antigravity": "1.5.16",
	})
	stubExec(t, func(string, ...string) *exec.Cmd {
		t.Fatal("up-to-date agents invoked podman")
		return nil
	})
	code, _, errb := capture(t, func() int { return runImages([]string{"update"}) })
	if code != 0 {
		t.Fatalf("update = (%d, %q)", code, errb)
	}
	if !strings.Contains(errb, "all selected agents are up to date") {
		t.Fatalf("stderr = %q", errb)
	}
}

func TestRootUsesInstalledImageAndVersion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENTBOX_STATE_DIR", dir)
	seedInstalledState(t, map[string]string{"opencode": "2.4.1"})
	var got policy.Request
	stubRun(t, func(_ session.Options, _ agent.Definition, req policy.Request) (int, error) {
		got = req
		return 0, nil
	})
	inv := cli.Invocation{Args: []string{"--agent", "opencode"}}
	if code := runRoot(inv); code != 0 {
		t.Fatalf("runRoot = %d", code)
	}
	if got.Image != "localhost/agentbox/opencode:2.4.1" || got.ImageVersion != "2.4.1" {
		t.Fatalf("request image/version = %q/%q", got.Image, got.ImageVersion)
	}
}
