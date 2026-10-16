// Package podman renders a ResolvedSpec into a podman argv and runs it.
//
// The split matters: argv.go and invariants.go are pure functions of the spec,
// so every security-relevant flag can be asserted in a unit test without a
// container runtime. run.go is the only part that touches the world.
//
// Arguments are passed as an []string to exec, never through a shell and never
// by string concatenation of user paths. That removes shell injection as a
// category rather than trying to escape it.
package podman

import (
	"strconv"

	"container-agent/internal/policy"
)

// Argv renders the full podman argument list, excluding the program name.
func Argv(spec *policy.ResolvedSpec, opts Options) []string {
	args := []string{"run"}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	args = append(args, "--rm")

	if opts.Interactive {
		args = append(args, "-i")
	}
	if opts.TTY {
		args = append(args, "-t")
	}

	// Hardening. These are constants of the design, not options, which is why
	// they are emitted here rather than accepted as parameters.
	if spec.Userns != "" {
		args = append(args, "--userns", spec.Userns)
	}
	if spec.CapDrop {
		args = append(args, "--cap-drop", "ALL")
	}
	if spec.NoNewPrivileges {
		args = append(args, "--security-opt", "no-new-privileges")
	}
	if spec.ReadOnly {
		args = append(args, "--read-only")
	}

	// --http-proxy defaults to true, which injects the host's proxy variables —
	// frequently credentialed — into every container. It must be disabled
	// explicitly; leaving it unset silently contradicts "nothing from the host
	// environment crosses".
	if !spec.HTTPProxy {
		args = append(args, "--http-proxy=false")
	}

	// Drop podman's default environment entirely. Anything that should exist is
	// listed explicitly below.
	if spec.UnsetEnv {
		args = append(args, "--unsetenv-all")
	}

	args = append(args, "--pids-limit", strconv.Itoa(spec.Limits.Pids))
	if spec.Limits.Memory != "" {
		args = append(args, "--memory", spec.Limits.Memory)
	}
	if spec.Limits.CPUs != "" {
		args = append(args, "--cpus", spec.Limits.CPUs)
	}

	if spec.Network.Mode != "" {
		args = append(args, "--network", spec.Network.Mode)
	}

	for _, t := range spec.Tmpfs {
		args = append(args, "--tmpfs", t)
	}

	for _, e := range spec.Env {
		args = append(args, "--env", e.Name+"="+e.Value)
	}

	for _, m := range spec.Mounts {
		args = append(args, "--volume", m.Host+":"+m.Dest+":"+m.Access.String())
	}

	if spec.Workdir != "" {
		args = append(args, "--workdir", spec.Workdir)
	}

	args = append(args, spec.Image)
	args = append(args, spec.Command...)
	return args
}

// SeededFilesMountDest is where session stages allow-listed seed files for the
// entrypoint to copy into the agent's writable config directory.
const SeededFilesMountDest = "/run/container-agent/seeds"

// Options are the parts of a run that are not decisions about security.
type Options struct {
	Name        string
	Interactive bool
	TTY         bool
}
