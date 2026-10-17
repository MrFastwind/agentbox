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
		Userns:          "keep-id",
		CapDrop:         true,
		NoNewPrivileges: true,
		ReadOnly:        true,
		UnsetEnv:        true,
		HTTPProxy:       false,
	}
	var refusals []Refusal

	if req.Image != "" {
		if err := ValidateImageRef(req.Image); err != nil {
			refusals = append(refusals, refusal(RefusalImage, req.Image, err.Error()))
		} else {
			spec.Image = req.Image
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

	switch def.Strategy {
	case agent.StrategyMount:
		mounts, refs := r.agentConfigMounts(def, deny)
		spec.Mounts = append(spec.Mounts, mounts...)
		refusals = append(refusals, refs...)
	case agent.StrategySeed:
		seeds, refs := collectSeeds(r.FS, def, r.Strict)
		spec.Seed = seeds
		refusals = append(refusals, refs...)
	case agent.StrategyNone:
		// Intentionally nothing: no host path is read, mounted or seeded.
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
