package podman

import (
	"fmt"
	"strings"

	"agentbox/internal/agent"
	"agentbox/internal/policy"
)

// forbiddenFlags may never appear in a rendered argv. They are listed by prefix
// so both "--flag value" and "--flag=value" spellings are caught.
//
// This exists because the tempting fix for a write failure or a missing device
// inside the sandbox is always to relax the sandbox. A unit test that fails the
// build is a better place to catch that than a review.
var forbiddenFlags = []string{
	"--privileged",
	"--cap-add",
	"--device",
	"--device-cgroup-rule",
	"--env-file",
	"--secret",
	"--runtime",
	"--hook",
	"--annotation",
}

// forbiddenValues are flag=value pairs that must never be emitted.
var forbiddenValues = []string{
	"--security-opt=seccomp=unconfined",
	"seccomp=unconfined",
	"--security-opt=apparmor=unconfined",
	"--security-opt=label=disable",
	"--read-only=false",
	"--http-proxy=true",
}

// Assert checks the invariants the design depends on and returns an error
// describing the first violation.
//
// It takes the spec as well as the rendered argv so that writable mounts can be
// classified by origin rather than counted blindly. Exactly one writable mount
// is allowed that the *user* can influence (the workspace, or an explicit
// --mount); the ephemeral HOME is writable too, but it is this program's own
// directory, created 0700, removed on exit, so it is not a user-facing hole.
func Assert(spec *policy.ResolvedSpec, args []string) error {
	for _, a := range args {
		for _, f := range forbiddenFlags {
			if a == f || strings.HasPrefix(a, f+"=") {
				return fmt.Errorf("argv contains forbidden flag %q", a)
			}
		}
		for _, fv := range forbiddenValues {
			if a == fv {
				return fmt.Errorf("argv contains forbidden argument %q", a)
			}
		}
		if isLoosenedMode(a) {
			return fmt.Errorf("argv contains loosened tmpfs mode %q", a)
		}
	}

	if !contains(args, "--http-proxy=false") {
		return fmt.Errorf("argv must always disable http-proxy injection")
	}
	if !contains(args, "--unsetenv-all") {
		return fmt.Errorf("argv must always unset podman's default environment")
	}
	if !contains(args, "--cap-drop") {
		return fmt.Errorf("argv must always drop capabilities")
	}
	if !contains(args, "--read-only") {
		return fmt.Errorf("argv must always make the root filesystem read-only")
	}
	if !contains(args, "--ulimit") || !contains(args, "core=0") {
		return fmt.Errorf("argv must always disable core dumps (--ulimit core=0)")
	}
	if !hasSeccompProfile(args) {
		return fmt.Errorf("argv must always install a seccomp profile (--security-opt seccomp=<path>)")
	}

	// The sandbox must carry an explicit, valid hostname that the spec agreed
	// to. This check runs after the always-on flags above so that a crafted
	// argv missing several flags reports the first one it violates.
	if spec.Hostname == "" {
		return fmt.Errorf("spec has no hostname; every run must be named agentbox-<agent> or an override")
	}
	if err := policy.ValidateHostname(spec.Hostname); err != nil {
		return fmt.Errorf("spec hostname is invalid: %w", err)
	}
	{
		var found bool
		for i, a := range args {
			if a == "--hostname" {
				if i+1 >= len(args) {
					return fmt.Errorf("--hostname without a value")
				}
				if found {
					return fmt.Errorf("argv contains --hostname more than once")
				}
				found = true
				if args[i+1] != spec.Hostname {
					return fmt.Errorf("argv hostname %q disagrees with the spec's %q", args[i+1], spec.Hostname)
				}
			}
		}
		if !found {
			return fmt.Errorf("argv must always carry --hostname %s", spec.Hostname)
		}
	}

	// Every write target must be one this program understands.
	userWritable := 0
	fromSpec := 0
	for _, m := range spec.Mounts {
		if m.Access != policy.RW {
			continue
		}
		fromSpec++
		switch m.Origin {
		case "launch-dir", "extra":
			userWritable++
		case "state":
			if m.Dest != agent.ContainerHome {
				return fmt.Errorf("ephemeral state is writable at %s, not %s", m.Dest, agent.ContainerHome)
			}
		default:
			return fmt.Errorf("writable mount with unrecognised origin %q at %s", m.Origin, m.Dest)
		}
	}
	if userWritable > 1 {
		return fmt.Errorf("spec has %d user-influenced writable mounts; at most one (the workspace) is allowed", userWritable)
	}

	// The argv must not disagree with the spec about what is writable.
	fromArgv := 0
	for i, a := range args {
		if a == "--volume" && i+1 < len(args) && strings.HasSuffix(args[i+1], ":rw") {
			fromArgv++
		}
	}
	if fromArgv != fromSpec {
		return fmt.Errorf("argv has %d writable mounts but the spec has %d", fromArgv, fromSpec)
	}

	return nil
}

// isLoosenedMode catches tmpfs mounts with a world- or group-writable mode.
// The state directories are created 0700 by the entrypoint precisely so that
// the mount itself never needs to be relaxed.
func isLoosenedMode(arg string) bool {
	for _, exact := range []string{
		"mode=1777", "mode=777", "mode=0777",
		"mode=0666", "mode=666", "mode=0667", "mode=667",
		"mode=0776", "mode=776", "mode=0677", "mode=677",
	} {
		if strings.Contains(arg, exact) {
			return true
		}
	}
	return false
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// hasSeccompProfile reports whether args carry a non-empty seccomp profile. The
// forbidden-values pass already rejects "seccomp=unconfined"; this requires the
// option to be present at all, so a run can never happen without one.
func hasSeccompProfile(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "seccomp=") && len(a) > len("seccomp=") {
			return true
		}
	}
	return false
}
