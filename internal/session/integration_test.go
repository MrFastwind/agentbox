package session

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
	"agentbox/internal/policy"
)

// The integration tests run the real runtime against a real sandbox image. They
// are opt-in because they need podman and a built image, and because they are
// slow. They skip — never fail — when a prerequisite is missing, so an ordinary
// `go test ./...` stays green on a machine without a container runtime.
//
//	AGENTBOX_INTEGRATION=1 \
//	AGENTBOX_TEST_IMAGE=localhost/agentbox/base:latest \
//	go test ./internal/session/ -run Integration -v
//
// They assert the promises that only mean anything end to end: the workspace is
// writable by default and read-only on request, HOME is private to the mapped
// user, a pre-trusted workspace path never crosses, host proxy variables never
// cross, and --network=none really has no interface but loopback.
func integrationImage(t *testing.T) string {
	t.Helper()
	if os.Getenv("AGENTBOX_INTEGRATION") != "1" {
		t.Skip("set AGENTBOX_INTEGRATION=1 to run integration tests")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman is not installed")
	}
	image := os.Getenv("AGENTBOX_TEST_IMAGE")
	if image == "" {
		image = "localhost/agentbox/base:latest"
	}
	if out, err := exec.Command("podman", "image", "exists", image).CombinedOutput(); err != nil {
		t.Skipf("test image %s is not built: %s", image, strings.TrimSpace(string(out)))
	}
	return image
}

// probeScript runs inside the sandbox and reports the facts under test as
// key=value lines. It only reads; it never writes, so it works under a
// read-only root and a read-only workspace.
const probeScript = `set -eu
echo "workspace_opts=$(awk '$2=="/workspace"{print $4; exit}' /proc/mounts)"
echo "home_mode=$(stat -c %a "$HOME")"
echo "home_uid=$(stat -c %u "$HOME")"
if [ -e "$HOME/.config/opencode/trust.json" ]; then echo "trust=present"; else echo "trust=absent"; fi
echo "proxy=$(env | grep -ci proxy || true)"
echo "nics=$(ls /sys/class/net | tr '\n' ',')"`

func parseProbe(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

// bootProbe runs one sandbox with the probe as its command and returns the
// probe's stdout and the exit code. The sandbox's real stdout is wired to a pipe
// so the probe output can be inspected without parsing podman's own chatter.
func bootProbe(t *testing.T, image, agentName string, noUserConfig bool, req policy.Request) (map[string]string, int) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	reg := agent.New(home)
	def, err := reg.Get(agentName)
	if err != nil {
		t.Fatal(err)
	}
	if noUserConfig {
		if def, err = reg.WithoutUserConfig(agentName); err != nil {
			t.Fatal(err)
		}
	}
	req.AgentName = agentName
	req.Image = image
	req.Command = []string{"sh", "-c", probeScript}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	opts := Options{
		Resolver: policy.NewResolver(fsx.Real{}, os.LookupEnv),
		Stdout:   w,
		Stderr:   w,
	}
	code, err := opts.Boot(def, req)
	w.Close()
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return parseProbe(b.String()), code
}

func TestIntegrationWorkspaceMountAccess(t *testing.T) {
	image := integrationImage(t)
	for _, tc := range []struct {
		name string
		ro   bool
		want string
	}{
		{"writable by default", false, "rw"},
		{"read-only on request", true, "ro"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, code := bootProbe(t, image, "shell", true, policy.Request{
				LaunchDir:         t.TempDir(),
				ReadOnlyWorkspace: tc.ro,
			})
			if code != 0 {
				t.Fatalf("exit %d: %+v", code, got)
			}
			if opts := got["workspace_opts"]; !strings.Contains(opts, tc.want) {
				t.Fatalf("workspace mount options = %q, want to contain %q", opts, tc.want)
			}
		})
	}
}

func TestIntegrationStateHomeIsPrivateToMappedUser(t *testing.T) {
	image := integrationImage(t)
	got, code := bootProbe(t, image, "shell", true, policy.Request{LaunchDir: t.TempDir()})
	if code != 0 {
		t.Fatalf("exit %d: %+v", code, got)
	}
	if got["home_mode"] != "700" {
		t.Fatalf("HOME mode = %q, want 700", got["home_mode"])
	}
	if want := strconv.Itoa(os.Getuid()); got["home_uid"] != want {
		t.Fatalf("HOME uid = %q, want %s (--userns=keep-id must map the invoker)", got["home_uid"], want)
	}
}

// A pre-trusted workspace path is a credential: it tells the agent it may run
// without asking. It must never be mounted or seeded, in either config mode.
func TestIntegrationTrustFileNeverCrosses(t *testing.T) {
	image := integrationImage(t)
	t.Run("without user config", func(t *testing.T) {
		got, code := bootProbe(t, image, "shell", true, policy.Request{LaunchDir: t.TempDir()})
		if code != 0 {
			t.Fatalf("exit %d: %+v", code, got)
		}
		if got["trust"] != "absent" {
			t.Fatalf("trust.json crossed into the sandbox: %+v", got)
		}
	})
	t.Run("with user config", func(t *testing.T) {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(home, ".config", "opencode")); err != nil {
			t.Skip("no host opencode config to exercise the seed path")
		}
		got, code := bootProbe(t, image, "opencode", false, policy.Request{LaunchDir: t.TempDir()})
		if code != 0 {
			t.Fatalf("exit %d: %+v", code, got)
		}
		if got["trust"] != "absent" {
			t.Fatalf("trust.json crossed into the sandbox: %+v", got)
		}
	})
}

func TestIntegrationHostProxyNeverCrosses(t *testing.T) {
	image := integrationImage(t)
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:3128")
	t.Setenv("http_proxy", "http://proxy.invalid:3128")
	got, code := bootProbe(t, image, "shell", true, policy.Request{LaunchDir: t.TempDir()})
	if code != 0 {
		t.Fatalf("exit %d: %+v", code, got)
	}
	if got["proxy"] != "0" {
		t.Fatalf("host proxy variables crossed into the sandbox: %+v", got)
	}
}

func TestIntegrationNetworkNoneHasOnlyLoopback(t *testing.T) {
	image := integrationImage(t)
	got, code := bootProbe(t, image, "shell", true, policy.Request{
		LaunchDir:   t.TempDir(),
		NetworkMode: "none",
	})
	if code != 0 {
		t.Fatalf("exit %d: %+v", code, got)
	}
	if nics := got["nics"]; nics != "lo," {
		t.Fatalf("interfaces under --network=none = %q, want only loopback", nics)
	}
}
