package policy

import (
	"fmt"
	"path/filepath"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
)

// Resolver turns a Request into a ResolvedSpec. It is the only place that
// decides anything, and it is pure with respect to the injected FS: given the
// same inputs it produces the same decisions, which is what makes the security
// surface exhaustively testable without a container runtime.
type Resolver struct {
	FS        fsx.FS
	LookupEnv func(string) (string, bool)
	Egress    EgressPolicy

	// Strict promotes "this is auditable" to "this is refused" for host
	// configuration that carries credential-shaped keys. It exists because the
	// question "is the agent inside the sandbox trusted?" is not answered by the
	// tool; a user who treats the agent as adversarial wants the refusal, and a
	// user who trusts their own configuration wants the mount.
	Strict bool
}

func NewResolver(fs fsx.FS, lookupEnv func(string) (string, bool)) *Resolver {
	return &Resolver{FS: fs, LookupEnv: lookupEnv, Egress: DefaultEgress{}}
}

// denyList builds this resolver's deny-list from the home directory it can
// see. Resolve computes its own with the same two calls so that an unresolvable
// home stays a hard error there; this fallback exists for AgentConfigDecisions,
// which has no launch directory to fail on.
func (r *Resolver) denyList() DenyList {
	home, err := r.FS.UserHomeDir()
	if err != nil || home == "" {
		return NewDenyList("/")
	}
	resolved, err := r.FS.EvalSymlinks(home)
	if err != nil {
		resolved = home
	}
	return NewDenyList(resolved)
}

// AgentConfigDecisions reports what mounting one agent's configuration
// directory would do — the mounts it would create, and the refusals it would
// record — without needing a request, a launch directory or a runtime.
//
// doctor uses it so that symlink handling is visible before anything is run:
// which config links are followed, and which are skipped and why. Without it
// those decisions reach only the audit log, and a user discovers a skipped
// link by the agent failing to find its skills.
func (r *Resolver) AgentConfigDecisions(def agent.Definition) ([]ResolvedMount, []Refusal) {
	return r.agentConfigMounts(def, r.denyList())
}

// ContainerWorkdir is where the launch directory appears.
const ContainerWorkdir = "/workspace"

func (r *Resolver) Resolve(def agent.Definition, req Request) (*ResolvedSpec, error) {
	home, err := r.FS.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locating home directory: %w", err)
	}
	resolvedHome, err := r.FS.EvalSymlinks(home)
	if err != nil {
		return nil, fmt.Errorf("resolving home directory: %w", err)
	}
	deny := NewDenyList(resolvedHome)

	spec := &ResolvedSpec{
		Agent:           def.Name,
		Image:           def.Image,
		Workdir:         ContainerWorkdir,
		UserConfig:      def.Strategy != agent.StrategyNone,
		Hostname:        DefaultHostname(def.Name),
		Userns:          "keep-id",
		CapDrop:         true,
		NoNewPrivileges: true,
		ReadOnly:        true,
		UnsetEnv:        true,
		HTTPProxy:       false,
	}
	var refusals []Refusal

	// Named-instance paths are program-owned, but they are still validated
	// here: a caller bug or a tampered instance file must not be able to point
	// one instance at another instance's config or HOME, or at a protected
	// host path.
	if req.InstanceName != "" {
		spec.Instance = req.InstanceName
		spec.Hostname = DefaultInstanceHostname(req.InstanceName)
		if err := ValidateInstanceName(req.InstanceName); err != nil {
			refusals = append(refusals, refusal(RefusalInstance, req.InstanceName, err.Error()))
		}
		if req.InstanceRoot == "" {
			refusals = append(refusals, refusal(RefusalInstance, req.InstanceName, "instance root is empty"))
		} else {
			root := filepath.Clean(req.InstanceRoot)
			if err := ValidateInstanceRoot(resolvedHome, root); err != nil {
				refusals = append(refusals, refusal(RefusalInstance, root, err.Error()))
			} else if real, err := r.FS.EvalSymlinks(root); err != nil {
				refusals = append(refusals, refusal(RefusalInstance, root, "cannot resolve: "+err.Error()))
			} else if real != root {
				refusals = append(refusals, refusal(RefusalInstance, root, "resolves to "+real+"; refusing a symlinked store"))
			} else if fi, err := r.FS.Lstat(root); err != nil || !fi.IsDir() {
				refusals = append(refusals, refusal(RefusalInstance, root, "is not a directory"))
			} else if fi.Mode().Perm()&0o077 != 0 {
				refusals = append(refusals, refusal(RefusalInstance, root, "must not be group- or world-accessible"))
			}

			if req.InstanceHome != "" {
				homePath := filepath.Join(root, req.InstanceName, "home")
				if filepath.Clean(req.InstanceHome) != homePath {
					refusals = append(refusals, refusal(RefusalInstance, req.InstanceHome,
						"is not the home directory of instance "+req.InstanceName))
				} else if err := validateInstanceDir(r.FS, homePath); err != nil {
					refusals = append(refusals, refusal(RefusalInstance, homePath, err.Error()))
				} else {
					spec.InstanceHome = homePath
					spec.Mounts = append(spec.Mounts, ResolvedMount{
						Host: homePath, Dest: agent.ContainerHome, Access: RW, Origin: "state",
					})
				}
			}

			if req.ConfigRoot != "" && !req.NoUserConfig {
				configPath := filepath.Join(root, req.InstanceName, "config")
				if filepath.Clean(req.ConfigRoot) != configPath {
					refusals = append(refusals, refusal(RefusalInstance, req.ConfigRoot,
						"is not the config directory of instance "+req.InstanceName))
				} else if err := validateInstanceDir(r.FS, configPath); err != nil {
					refusals = append(refusals, refusal(RefusalInstance, configPath, err.Error()))
				}
			}
		}
	}

	if req.Image != "" {
		if err := ValidateImageRef(req.Image); err != nil {
			refusals = append(refusals, refusal(RefusalImage, req.Image, err.Error()))
		} else {
			spec.Image = req.Image
		}
	}

	if req.ImageVersion != "" {
		if err := ValidateAgentVersion(req.ImageVersion); err != nil {
			refusals = append(refusals, refusal(RefusalImage, req.ImageVersion, err.Error()))
		} else {
			spec.ImageVersion = req.ImageVersion
		}
	}
	if req.ImageDigest != "" {
		if err := ValidateImageDigest(req.ImageDigest); err != nil {
			refusals = append(refusals, refusal(RefusalImage, req.ImageDigest, err.Error()))
		} else {
			spec.ImageDigest = req.ImageDigest
		}
	}

	// The hostname is identity, not a capability, but it is still validated
	// here rather than at run time: a malformed value would otherwise fail
	// inside podman, after staging has already begun.
	if req.Hostname != "" {
		if err := ValidateHostname(req.Hostname); err != nil {
			refusals = append(refusals, refusal(RefusalHostname, req.Hostname, err.Error()))
		} else {
			spec.Hostname = req.Hostname
		}
	}

	limits, lrefs := resolveLimits(req.Memory, req.CPUs, req.PidsLimit)
	spec.Limits = limits
	refusals = append(refusals, lrefs...)

	network, err := r.Egress.Decide(req.NetworkMode)
	if err != nil {
		return nil, &Error{Refusals: []Refusal{refusal(RefusalNetwork, req.NetworkMode, err.Error())}}
	}
	spec.Network = network
	if network.Warning != "" {
		refusals = append(refusals, warn(RefusalNetwork, network.Mode, network.Warning))
	}

	// Launch directory. This is a mount request like any other and is validated
	// the same way: it is not exempt just because it was detected rather than
	// typed.
	launch := req.WorkdirOverride
	if launch == "" {
		launch = req.LaunchDir
	}
	if launch == "" {
		wd, err := r.FS.Getwd()
		if err != nil {
			return nil, fmt.Errorf("determining launch directory: %w", err)
		}
		launch = wd
	}

	// --workspace narrows (or moves) the mount to a subdirectory of the launch
	// directory. It is validated by the same rules as any other launch path, so
	// an escape ("..") that lands on a protected path is still refused.
	if req.WorkspaceOverride != "" {
		if filepath.IsAbs(req.WorkspaceOverride) {
			launch = req.WorkspaceOverride
		} else {
			launch = filepath.Join(launch, req.WorkspaceOverride)
		}
	}

	absLaunch, err := r.FS.Abs(launch)
	if err != nil {
		return nil, fmt.Errorf("resolving launch directory %s: %w", launch, err)
	}
	resolvedLaunch, err := r.FS.EvalSymlinks(absLaunch)
	if err != nil {
		refusals = append(refusals, refusal(RefusalLaunchDir, launch, "cannot resolve: "+err.Error()))
	} else if err := deny.ValidateMount(resolvedLaunch); err != nil {
		refusals = append(refusals, refusal(RefusalLaunchDir, resolvedLaunch, err.Error()))
	} else {
		workspaceAccess := RW
		if req.ReadOnlyWorkspace {
			workspaceAccess = RO
		}
		spec.Mounts = append(spec.Mounts, ResolvedMount{
			Host: resolvedLaunch, Dest: ContainerWorkdir, Access: workspaceAccess, Origin: "launch-dir",
		})
	}

	for _, raw := range req.ExtraMounts {
		m, ref, ok := r.explicitMount(deny, raw)
		if !ok {
			refusals = append(refusals, ref)
			continue
		}
		spec.Mounts = append(spec.Mounts, m)
	}

	// Configuration source. --no-user-config wins over everything, including an
	// instance clone: it is the explicit "read no host config" switch.
	configDir := def.ConfigDir
	configSource := "host"
	switch {
	case req.NoUserConfig || def.Strategy == agent.StrategyNone:
		configSource = "none"
	case req.ConfigRoot != "":
		configDir = req.ConfigRoot
		configSource = "instance"
	}
	spec.ConfigSource = configSource
	spec.UserConfig = configSource != "none"

	if configSource != "none" {
		switch def.Strategy {
		case agent.StrategyMount:
			prefixes := def.SymlinkTargetPrefixes
			if configSource == "instance" {
				// The clone materialises top-level links, so the only path a
				// remaining link may point at is the clone root itself.
				prefixes = []string{configDir}
			}
			mounts, refs := r.agentConfigMountsFrom(def, configDir, deny, prefixes)
			spec.Mounts = append(spec.Mounts, mounts...)
			refusals = append(refusals, refs...)
		case agent.StrategySeed:
			seeds, refs := collectSeedsFrom(r.FS, def, configDir, r.Strict)
			spec.Seed = seeds
			refusals = append(refusals, refs...)
		case agent.StrategyNone:
			// Intentionally nothing: no host path is read, mounted or seeded.
		}
	}

	// Credentials are never read by default. --user-auth is the one explicit
	// exception, and the registry allow-list is still the boundary: this flag
	// cannot name an arbitrary path.
	spec.UserAuth = req.UserAuth
	if req.UserAuth {
		switch {
		case req.NoUserConfig:
			refusals = append(refusals, refusal(RefusalAuth, "--user-auth",
				"conflicts with --no-user-config, which promises that no host path is read"))
		case req.InstanceName != "":
			refusals = append(refusals, refusal(RefusalAuth, "--user-auth",
				"is not supported for named instances: their HOME is persistent, so credentials would be stored on disk"))
		case len(def.AuthFiles) == 0:
			refusals = append(refusals, refusal(RefusalAuth, def.Name,
				"has no authentication files declared"))
		default:
			auth, refs := collectAuth(r.FS, resolvedHome, def)
			spec.Auth = auth
			refusals = append(refusals, refs...)
		}
	}

	env, erefs := resolveEnv(def, req.EnvNames, r.LookupEnv)
	spec.Env = env
	refusals = append(refusals, erefs...)

	spec.WritableStateDirs = append(spec.WritableStateDirs, def.StateDirs...)

	spec.Command = req.Command
	if len(spec.Command) == 0 {
		if len(def.Command) > 0 {
			spec.Command = def.Command
		} else {
			spec.Command = []string{"/bin/bash", "-l"}
		}
	}

	spec.Refusals = refusals
	if err := fatalError(refusals); err != nil {
		return nil, err
	}
	return spec, nil
}
