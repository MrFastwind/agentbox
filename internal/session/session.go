// Package session orchestrates one run: resolve, stage, audit, execute.
//
// It is the only impure layer. Everything it decides has already been decided
// by internal/policy; its job is to carry out those decisions faithfully and to
// clean up.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agentbox/internal/agent"
	"agentbox/internal/audit"
	"agentbox/internal/podman"
	"agentbox/internal/policy"
)

// Options configures a boot.
type Options struct {
	Resolver *policy.Resolver
	Audit    *audit.Logger

	// Name is the container name; generated when empty.
	Name string

	Stdin  *os.File
	Stdout *os.File
	Stderr *os.File
	TTY    bool

	// PrintArgv renders the argv and exits without running podman. Staging
	// still happens, so the printed argv is the real one.
	PrintArgv bool
}

// runPodman is podman.Run, indirected so the boot path can be tested end to end
// without a container runtime: a test substitutes a function that captures the
// resolved spec and rendered argv.
var runPodman = podman.Run

// Boot resolves the request and runs the sandbox, returning the inner exit code.
func (o Options) Boot(def agent.Definition, req policy.Request) (int, error) {
	spec, err := o.Resolver.Resolve(def, req)
	if err != nil {
		return 1, err
	}

	var cleanups []func()
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()

	// The container's HOME.
	//
	// This cannot be a podman --tmpfs: podman creates one owned by container 0
	// with mode 0700 and rejects uid=/gid= on --tmpfs, so under keep-id the
	// agent cannot write its own HOME. Instead the state lives in a directory
	// this process creates 0700 and owns, on a tmpfs where one is available, and
	// is removed on exit. The agent gets a writable HOME; nothing it writes
	// survives, and nothing it writes is owned by anyone else.
	stateDir, err := ephemeralDir("agentbox-state-")
	if err != nil {
		return 1, fmt.Errorf("creating ephemeral home: %w", err)
	}
	cleanups = append(cleanups, func() { os.RemoveAll(stateDir) })

	if err := prepareStateDirs(stateDir, spec.WritableStateDirs); err != nil {
		return 1, err
	}
	spec.Mounts = append(spec.Mounts, policy.ResolvedMount{
		Host:   stateDir,
		Dest:   agent.ContainerHome,
		Access: policy.RW,
		Origin: "state",
	})

	// Allow-listed seed files, staged read-only for the entrypoint to copy into
	// the writable config directory.
	if len(spec.Seed) > 0 {
		seedDir, err := ephemeralDir("agentbox-seeds-")
		if err != nil {
			return 1, fmt.Errorf("creating seed staging directory: %w", err)
		}
		cleanups = append(cleanups, func() { os.RemoveAll(seedDir) })

		if err := writeSeeds(seedDir, spec.Seed); err != nil {
			return 1, err
		}
		spec.Mounts = append(spec.Mounts, policy.ResolvedMount{
			Host:   seedDir,
			Dest:   podman.SeededFilesMountDest,
			Access: policy.RO,
			Origin: "seed",
		})
	}

	name := o.Name
	if name == "" {
		name = "agentbox-" + shortID()
	}

	// The seccomp profile podman installs, denying the syscalls that create
	// nested user namespaces. It is written to its own 0700 directory and read
	// from there; it is never mounted into the container.
	seccompDir, err := ephemeralDir("agentbox-seccomp-")
	if err != nil {
		return 1, fmt.Errorf("creating seccomp staging directory: %w", err)
	}
	cleanups = append(cleanups, func() { os.RemoveAll(seccompDir) })
	seccompPath := filepath.Join(seccompDir, podman.SeccompProfileName)
	if err := os.WriteFile(seccompPath, podman.SeccompProfile(), 0o600); err != nil {
		return 1, fmt.Errorf("staging seccomp profile: %w", err)
	}

	args := podman.Argv(spec, podman.Options{
		Name:           name,
		Interactive:    true,
		TTY:            o.TTY,
		SeccompProfile: seccompPath,
	})
	if err := podman.Assert(spec, args); err != nil {
		return 1, err
	}

	if o.Audit != nil {
		if err := o.Audit.Record(spec, args); err != nil {
			return 1, err
		}
	}

	if o.PrintArgv {
		fmt.Fprintln(o.Stdout, shellQuote(args))
		return 0, nil
	}

	return runPodman(spec, args, o.Stdin, o.Stdout, o.Stderr)
}

// prepareStateDirs creates the writable state directories on the host side of
// the HOME bind mount, mapped from their container paths.
//
// Doing this before podman starts matters for a second reason beyond ownership:
// it creates the intermediate directories that read-only configuration mounts
// are placed into. Otherwise podman creates that chain itself, owned by
// container root, and the agent cannot write to its own XDG_CONFIG_HOME.
func prepareStateDirs(stateDir string, containerPaths []string) error {
	for _, p := range containerPaths {
		rel := strings.TrimPrefix(p, agent.ContainerHome)
		rel = strings.TrimPrefix(rel, "/")

		host := stateDir
		if rel != "" {
			host = filepath.Join(stateDir, filepath.FromSlash(rel))
		}
		if err := os.MkdirAll(host, 0o700); err != nil {
			return fmt.Errorf("preparing state directory %s: %w", p, err)
		}
		if err := os.Chmod(host, 0o700); err != nil {
			return fmt.Errorf("tightening state directory %s: %w", p, err)
		}
	}
	return nil
}

// writeSeeds writes the allow-listed files into the staging directory,
// mirroring their relative paths.
func writeSeeds(dir string, seeds []policy.SeededFile) error {
	for _, s := range seeds {
		dest := filepath.Join(dir, filepath.FromSlash(s.Rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return fmt.Errorf("staging %s: %w", s.Rel, err)
		}
		if err := os.WriteFile(dest, s.Data, 0o600); err != nil {
			return fmt.Errorf("staging %s: %w", s.Rel, err)
		}
	}
	return nil
}

func shortID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b[:])
}

// shellQuote renders an argv so that it can be pasted into a shell.
func shellQuote(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n\"'\\$`&|;<>()*?[]#~") {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}
