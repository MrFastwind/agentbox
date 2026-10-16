package podman_test

import (
	"testing"

	"agentbox/internal/podman"
)

// hardening returns an argv stub that already satisfies the four always-on
// invariants, so a test can isolate whatever it is actually probing.
func hardening() []string {
	return []string{"run", "--rm", "--http-proxy=false", "--unsetenv-all", "--cap-drop", "ALL", "--read-only"}
}

func TestArgvEmitsTmpfs(t *testing.T) {
	spec := baseSpec()
	spec.Tmpfs = []string{"/tmp", "/run"}
	args := podman.Argv(spec, podman.Options{Interactive: true})
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
	args := podman.Argv(spec, podman.Options{Interactive: true})
	if err := podman.Assert(spec, args); err == nil {
		t.Fatal("Assert must reject a state mount at an unexpected destination")
	}
}

// The spec and the rendered argv must agree on how many writable mounts exist.
func TestAssertRejectsWritableCountMismatch(t *testing.T) {
	spec := baseSpec() // one launch-dir RW mount plus the state mount
	args := hardening() // no --volume ...:rw at all
	if err := podman.Assert(spec, args); err == nil {
		t.Fatal("Assert must reject an argv whose writable mounts disagree with the spec")
	}
}

// A non-RW mount must never be rendered rw, and a matching spec/argv pair must
// pass: this pins the read-only side of the mount contract.
func TestAssertAcceptsReadOnlyExtras(t *testing.T) {
	spec := baseSpec()
	args := podman.Argv(spec, podman.Options{Interactive: true})
	for _, a := range args {
		if a == "/home/u/.config/opencode/opencode.json:/home/agent/.config/opencode/opencode.json:rw" {
			t.Fatal("a read-only config file was rendered writable")
		}
	}
	if err := podman.Assert(spec, args); err != nil {
		t.Fatalf("a valid spec/argv pair must pass Assert: %v", err)
	}
}
