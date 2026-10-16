package podman_test

import (
	"strings"
	"testing"

	"container-agent/internal/podman"
	"container-agent/internal/policy"
)

func baseSpec() *policy.ResolvedSpec {
	return &policy.ResolvedSpec{
		Agent:           "opencode",
		Image:           "localhost/container-agent/opencode:latest",
		Command:         []string{"opencode"},
		Workdir:         "/workspace",
		Userns:          "keep-id",
		CapDrop:         true,
		NoNewPrivileges: true,
		ReadOnly:        true,
		UnsetEnv:        true,
		HTTPProxy:       false,
		Limits:          policy.Limits{Memory: "4g", CPUs: "2", Pids: 2048},
		Network:         policy.NetworkDecision{Mode: "slirp4netns"},
		Mounts: []policy.ResolvedMount{
			{Host: "/home/u/project", Dest: "/workspace", Access: policy.RW, Origin: "launch-dir"},
			{Host: "/dev/shm/state", Dest: "/home/agent", Access: policy.RW, Origin: "state"},
			{Host: "/home/u/.config/opencode/opencode.json", Dest: "/home/agent/.config/opencode/opencode.json", Access: policy.RO, Origin: "agent-config"},
		},
		Env: []policy.EnvPair{{Name: "HOME", Value: "/home/agent"}},
	}
}

func TestArgvSatisfiesInvariants(t *testing.T) {
	spec := baseSpec()
	args := podman.Argv(spec, podman.Options{Name: "container-agent-test", Interactive: true, TTY: true})
	if err := podman.Assert(spec, args); err != nil {
		t.Fatalf("rendered argv violates invariants: %v\nargv: %v", err, args)
	}
}

func TestArgvDisablesProxyInjection(t *testing.T) {
	spec := baseSpec()
	args := podman.Argv(spec, podman.Options{Interactive: true})
	if !contains(args, "--http-proxy=false") {
		t.Fatalf("expected --http-proxy=false, got %v", args)
	}
}

func TestArgvDropsAmbientEnvironment(t *testing.T) {
	spec := baseSpec()
	args := podman.Argv(spec, podman.Options{Interactive: true})
	if !contains(args, "--unsetenv-all") {
		t.Fatalf("expected --unsetenv-all, got %v", args)
	}
}

func TestArgvEmitsHardening(t *testing.T) {
	spec := baseSpec()
	args := podman.Argv(spec, podman.Options{Interactive: true})
	for _, want := range []string{"--userns", "--cap-drop", "--security-opt", "--read-only"} {
		if !contains(args, want) {
			t.Errorf("expected %s in argv: %v", want, args)
		}
	}
}

func TestArgvNeverEnablesHostNetworkingByItself(t *testing.T) {
	args := podman.Argv(baseSpec(), podman.Options{Interactive: true})
	for i, a := range args {
		if a == "--network" && i+1 < len(args) && args[i+1] == "host" {
			t.Fatal("argv requested host networking from a spec that asked for slirp4netns")
		}
	}
}

// forbiddenArgv is a surrounding-frame helper: it builds a spec that cannot be
// rendered by Argv (the extra args are injected directly) so that Assert's
// argument-level checks can be exercised.
func assertDirect(args []string) error {
	return podman.Assert(baseSpec(), args)
}

func TestAssertRejectsPrivileged(t *testing.T) {
	args := []string{"run", "--rm", "--privileged", "--http-proxy=false", "--unsetenv-all", "--cap-drop", "ALL", "--read-only"}
	if err := assertDirect(args); err == nil {
		t.Fatal("Assert must reject --privileged")
	}
}

func TestAssertRejectsCapAdd(t *testing.T) {
	args := []string{"run", "--rm", "--cap-add=NET_ADMIN", "--http-proxy=false", "--unsetenv-all", "--cap-drop", "ALL", "--read-only"}
	if err := assertDirect(args); err == nil {
		t.Fatal("Assert must reject --cap-add")
	}
}

func TestAssertRejectsWritableRootfs(t *testing.T) {
	args := []string{"run", "--rm", "--read-only=false", "--http-proxy=false", "--unsetenv-all", "--cap-drop", "ALL", "--read-only"}
	if err := assertDirect(args); err == nil {
		t.Fatal("Assert must reject an explicitly writable root filesystem")
	}
}

func TestAssertRejectsUnconfinedSeccomp(t *testing.T) {
	args := []string{"run", "--rm", "--security-opt=seccomp=unconfined", "--http-proxy=false", "--unsetenv-all", "--cap-drop", "ALL", "--read-only"}
	if err := assertDirect(args); err == nil {
		t.Fatal("Assert must reject seccomp=unconfined")
	}
}

func TestAssertRejectsLoosenedTmpfsMode(t *testing.T) {
	args := []string{"run", "--rm", "--tmpfs", "/x:rw,mode=1777", "--http-proxy=false", "--unsetenv-all", "--cap-drop", "ALL", "--read-only"}
	if err := assertDirect(args); err == nil {
		t.Fatal("Assert must reject a world-writable tmpfs mode")
	}
}

func TestAssertRequiresProxyFlag(t *testing.T) {
	args := []string{"run", "--rm", "--unsetenv-all", "--cap-drop", "ALL", "--read-only"}
	if err := assertDirect(args); err == nil || !strings.Contains(err.Error(), "http-proxy") {
		t.Fatalf("Assert must require --http-proxy=false, got %v", err)
	}
}

// A second writable mount that the user could have asked for is refused, even
// though the ephemeral HOME is legitimately writable.
func TestAssertRejectsSecondUserWritableMount(t *testing.T) {
	spec := baseSpec()
	spec.Mounts = append(spec.Mounts, policy.ResolvedMount{
		Host: "/home/u/extra", Dest: "/extra", Access: policy.RW, Origin: "extra",
	})
	args := podman.Argv(spec, podman.Options{Interactive: true})
	if err := podman.Assert(spec, args); err == nil {
		t.Fatal("Assert must reject a second user-influenced writable mount")
	}
}

// A writable mount with an origin the design does not know is refused, so a
// future decision cannot quietly introduce an unclassified write target.
func TestAssertRejectsUnknownWritableOrigin(t *testing.T) {
	spec := baseSpec()
	spec.Mounts = append(spec.Mounts, policy.ResolvedMount{
		Host: "/tmp/xyz", Dest: "/mystery", Access: policy.RW, Origin: "surprise",
	})
	args := podman.Argv(spec, podman.Options{Interactive: true})
	if err := podman.Assert(spec, args); err == nil {
		t.Fatal("Assert must reject a writable mount with an unrecognised origin")
	}
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
