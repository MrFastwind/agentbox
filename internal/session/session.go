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

	// A decision not to mount something is a decision the user has to see.
	// Refusals reach the audit log either way, but an audit file nobody has
	// opened cannot explain why the agent has no skills directory — which is
	// precisely how a skipped config symlink gets noticed.
	if o.Stderr != nil {
		for _, ref := range spec.Refusals {
			if !ref.Fatal {
				fmt.Fprintf(o.Stderr, "agentbox: %s\n", ref.String())
			}
		}
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
	// agent cannot write its own HOME. An ad-hoc run therefore gets a directory
	// this process creates 0700 and owns, on a tmpfs where one is available,
	// and removes on exit. A named instance may instead point at its persistent
	// HOME, which policy has already validated and mounted; only `agentbox
	// remove` deletes that.
	stateDir := spec.InstanceHome
	persistentHome := stateDir != ""
	if !persistentHome {
		var err error
		stateDir, err = ephemeralDir("agentbox-state-")
		if err != nil {
			return 1, fmt.Errorf("creating ephemeral home: %w", err)
		}
		cleanups = append(cleanups, func() { os.RemoveAll(stateDir) })
	}

	if persistentHome {
		if err := prepareStateDirsNoFollow(stateDir, spec.WritableStateDirs); err != nil {
			return 1, err
		}
	} else if err := prepareStateDirs(stateDir, spec.WritableStateDirs); err != nil {
		return 1, err
	}
	if !persistentHome {
		spec.Mounts = append(spec.Mounts, policy.ResolvedMount{
			Host:   stateDir,
			Dest:   agent.ContainerHome,
			Access: policy.RW,
			Origin: "state",
		})
	}

	// Re-validate the mounts that were decided from host paths. Resolution
	// already resolved symlinks and applied the deny-list, but the filesystem
	// can change between that decision and the moment podman opens the path.
	// The state and seed mounts appended above are program-owned and are
	// skipped by Revalidate.
	if o.Resolver != nil {
		if err := o.Resolver.Revalidate(spec); err != nil {
			return 1, err
		}
	}

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

	// Credential files opted into with --user-auth. They are staged separately
	// from config seeds so the seed allow-list and its content scan keep their
	// original meaning, and they are copied into the ephemeral HOME by the
	// entrypoint rather than mounted over the host's own files.
	if len(spec.Auth) > 0 {
		authDir, err := ephemeralDir("agentbox-auth-")
		if err != nil {
			return 1, fmt.Errorf("creating auth staging directory: %w", err)
		}
		cleanups = append(cleanups, func() { os.RemoveAll(authDir) })

		if err := writeAuthFiles(authDir, spec.Auth); err != nil {
			return 1, err
		}
		spec.Mounts = append(spec.Mounts, policy.ResolvedMount{
			Host:   authDir,
			Dest:   podman.UserAuthMountDest,
			Access: policy.RO,
			Origin: "auth",
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
		if spec.ImageVersion != "" {
			fmt.Fprintf(o.Stdout, "# image %s version %s\n", spec.Image, spec.ImageVersion)
		}
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

// prepareStateDirsNoFollow is the persistent-HOME variant. The HOME survives
// between runs, so its contents are sandbox-writable and must be treated as
// hostile: walking with Lstat and refusing any symlink prevents a previous run
// from redirecting a later run's state directory at a host path.
func prepareStateDirsNoFollow(stateDir string, containerPaths []string) error {
	if fi, err := os.Lstat(stateDir); err != nil {
		return fmt.Errorf("checking instance home: %w", err)
	} else if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("instance home %s is not a real directory", stateDir)
	}
	for _, p := range containerPaths {
		rel := strings.TrimPrefix(p, agent.ContainerHome)
		rel = strings.TrimPrefix(rel, "/")
		cur := stateDir
		if rel == "" {
			continue
		}
		for _, part := range strings.Split(rel, "/") {
			if part == "" || part == "." || part == ".." {
				return fmt.Errorf("refusing unsafe state path %s", p)
			}
			next := filepath.Join(cur, part)
			fi, err := os.Lstat(next)
			if err != nil {
				if !os.IsNotExist(err) {
					return fmt.Errorf("checking state directory %s: %w", p, err)
				}
				if err := os.Mkdir(next, 0o700); err != nil {
					return fmt.Errorf("preparing state directory %s: %w", p, err)
				}
				fi, err = os.Lstat(next)
				if err != nil {
					return fmt.Errorf("checking state directory %s: %w", p, err)
				}
			}
			if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
				return fmt.Errorf("state directory %s is not a real directory", next)
			}
			if fi.Mode().Perm() != 0o700 {
				if err := os.Chmod(next, 0o700); err != nil {
					return fmt.Errorf("tightening state directory %s: %w", p, err)
				}
			}
			cur = next
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

// writeAuthFiles stages credential files under the container-home-relative path
// they will be copied to. The staging directory is read-only inside the
// container, and mode 0600 is preserved by the entrypoint's cp -a.
func writeAuthFiles(dir string, auth []policy.AuthFile) error {
	for _, a := range auth {
		dest := filepath.Join(dir, filepath.FromSlash(a.Rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return fmt.Errorf("staging auth file %s: %w", a.Rel, err)
		}
		if err := os.WriteFile(dest, a.Data, 0o600); err != nil {
			return fmt.Errorf("staging auth file %s: %w", a.Rel, err)
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
