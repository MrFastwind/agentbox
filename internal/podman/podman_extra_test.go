package podman_test

import (
	"encoding/json"
	"strings"
	"testing"

	"agentbox/internal/podman"
)

// testSeccomp is a stand-in profile path for rendering tests.
const testSeccomp = "/run/agentbox/seccomp.json"

// hardening returns an argv stub that already satisfies the four always-on
// invariants, so a test can isolate whatever it is actually probing.
func hardening() []string {
	return []string{
		"run", "--rm", "--hostname", "agentbox-opencode",
		"--http-proxy=false", "--unsetenv-all",
		"--cap-drop", "ALL", "--read-only", "--ulimit", "core=0",
		"--security-opt", "seccomp=" + testSeccomp,
	}
}

func TestArgvEmitsTmpfs(t *testing.T) {
	spec := baseSpec()
	spec.Tmpfs = []string{"/tmp", "/run"}
	args := podman.Argv(spec, podman.Options{Interactive: true, SeccompProfile: testSeccomp})
	if !contains(args, "--tmpfs") {
		t.Fatalf("expected --tmpfs in argv: %v", args)
	}
	// The values must be preserved verbatim, in order.
	var got []string
	for i, a := range args {
		if a == "--tmpfs" && i+1 < len(args) {
			got = append(got, args[i+1])
		}
	}
	if len(got) != 2 || got[0] != "/tmp" || got[1] != "/run" {
		t.Fatalf("tmpfs entries not emitted as specified: %v", got)
	}
}

func TestAssertRejectsForbiddenValues(t *testing.T) {
	cases := []struct {
		name string
		arg  string
	}{
		{"apparmor unconfined", "--security-opt=apparmor=unconfined"},
		{"label disabled", "--security-opt=label=disable"},
		{"http proxy injection", "--http-proxy=true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append(hardening(), tc.arg)
			if err := podman.Assert(baseSpec(), args); err == nil {
				t.Fatalf("Assert must reject %q", tc.arg)
			}
		})
	}
}

func TestAssertRejectsForbiddenFlagPrefixes(t *testing.T) {
	for _, arg := range []string{"--device=/dev/kvm", "--env-file=/tmp/env", "--secret=foo", "--runtime=runc"} {
		if err := podman.Assert(baseSpec(), append(hardening(), arg)); err == nil {
			t.Fatalf("Assert must reject %q", arg)
		}
	}
}

func TestAssertRequiresAlwaysOnFlags(t *testing.T) {
	cases := []struct {
		name   string
		remove string
	}{
		{"unsetenv-all", "--unsetenv-all"},
		{"cap-drop", "--cap-drop"},
		{"read-only", "--read-only"},
		{"http-proxy=false", "--http-proxy=false"},
		{"ulimit", "--ulimit"},
		{"seccomp", "seccomp=" + testSeccomp},
		{"hostname", "--hostname"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			for _, a := range hardening() {
				if a != tc.remove {
					args = append(args, a)
				}
			}
			if err := podman.Assert(baseSpec(), args); err == nil {
				t.Fatalf("Assert must require %s", tc.remove)
			}
		})
	}
}

// A writable state mount that is not the ephemeral HOME would hand the sandbox a
// write target outside the one hole the design allows.
func TestAssertRejectsStateAtWrongDestination(t *testing.T) {
	spec := baseSpec()
	for i := range spec.Mounts {
		if spec.Mounts[i].Origin == "state" {
			spec.Mounts[i].Dest = "/wrong"
		}
	}
	args := podman.Argv(spec, podman.Options{Interactive: true, SeccompProfile: testSeccomp})
	if err := podman.Assert(spec, args); err == nil {
		t.Fatal("Assert must reject a state mount at an unexpected destination")
	}
}

// The spec and the rendered argv must agree on how many writable mounts exist.
func TestAssertRejectsWritableCountMismatch(t *testing.T) {
	spec := baseSpec()  // one launch-dir RW mount plus the state mount
	args := hardening() // no --volume ...:rw at all
	if err := podman.Assert(spec, args); err == nil {
		t.Fatal("Assert must reject an argv whose writable mounts disagree with the spec")
	}
}

func TestArgvDisablesCoreDumps(t *testing.T) {
	args := podman.Argv(baseSpec(), podman.Options{Interactive: true, SeccompProfile: testSeccomp})
	val, ok := flagValue(args, "--ulimit")
	if !ok || val != "core=0" {
		t.Fatalf("argv must carry --ulimit core=0, got %v", args)
	}
}

// flagValue returns the token following the first occurrence of flag.
func flagValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func TestArgvInstallsSeccompProfile(t *testing.T) {
	args := podman.Argv(baseSpec(), podman.Options{Interactive: true, SeccompProfile: testSeccomp})
	if !contains(args, "seccomp="+testSeccomp) {
		t.Fatalf("argv must install the seccomp profile, got %v", args)
	}
	if err := podman.Assert(baseSpec(), args); err != nil {
		t.Fatalf("rendered argv with a seccomp profile must pass Assert: %v", err)
	}
}

func TestAssertRejectsMissingSeccompProfile(t *testing.T) {
	args := []string{
		"run", "--rm", "--http-proxy=false", "--unsetenv-all",
		"--cap-drop", "ALL", "--read-only", "--ulimit", "core=0",
	}
	if err := podman.Assert(baseSpec(), args); err == nil {
		t.Fatal("Assert must reject an argv with no seccomp profile")
	}
}

func TestAssertRejectsUnconfinedSeccompValue(t *testing.T) {
	args := append(hardening(), "--security-opt=seccomp=unconfined")
	if err := podman.Assert(baseSpec(), args); err == nil {
		t.Fatal("Assert must reject seccomp=unconfined")
	}
}

func TestSeccompProfileDeniesNestedUserns(t *testing.T) {
	var profile struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(podman.SeccompProfile(), &profile); err != nil {
		t.Fatalf("embedded seccomp profile is not valid JSON: %v", err)
	}
	if profile.DefaultAction != "SCMP_ACT_ALLOW" {
		t.Fatalf("profile should be allow-by-default, got %q", profile.DefaultAction)
	}
	denied := map[string]bool{}
	for _, sc := range profile.Syscalls {
		for _, n := range sc.Names {
			if strings.HasPrefix(sc.Action, "SCMP_ACT_ERRNO") {
				denied[n] = true
			}
		}
	}
	for _, want := range []string{"unshare", "clone", "clone3"} {
		if !denied[want] {
			t.Fatalf("seccomp profile must deny %s, got %+v", want, profile.Syscalls)
		}
	}
}

// A non-RW mount must never be rendered rw, and a matching spec/argv pair must
// pass: this pins the read-only side of the mount contract.
func TestAssertAcceptsReadOnlyExtras(t *testing.T) {
	spec := baseSpec()
	args := podman.Argv(spec, podman.Options{Interactive: true, SeccompProfile: testSeccomp})
	for _, a := range args {
		if a == "/home/u/.config/opencode/opencode.json:/home/agent/.config/opencode/opencode.json:rw" {
			t.Fatal("a read-only config file was rendered writable")
		}
	}
	if err := podman.Assert(spec, args); err != nil {
		t.Fatalf("a valid spec/argv pair must pass Assert: %v", err)
	}
}
