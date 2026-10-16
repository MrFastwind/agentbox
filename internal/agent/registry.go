// Package agent holds the per-agent registry.
//
// The registry is DATA. It declares facts about an agent — where its config
// lives, which files may be seeded, which environment names may cross — and it
// makes no security decisions. Every decision lives in internal/policy, so that
// a registry entry cannot weaken a universal invariant. In particular there is
// deliberately no "follow symlinks" toggle here: symlink resolution is a
// property of the sandbox, not a per-agent preference.
package agent

import (
	"fmt"
	"sort"
	"strings"
)

// Strategy is how an agent's host configuration is brought into the container.
type Strategy uint8

const (
	// StrategyNone reads no host config at all. This is what --no-user-config
	// selects: the same code path as every other mode, with different data.
	StrategyNone Strategy = iota
	// StrategySeed copies individual allow-listed files. Needed by agents that
	// keep config and secrets in one directory and cannot mount it read-only.
	StrategySeed
	// StrategyMount bind-mounts the config directory read-only.
	StrategyMount
)

func (s Strategy) String() string {
	switch s {
	case StrategyNone:
		return "none"
	case StrategySeed:
		return "seed"
	case StrategyMount:
		return "mount"
	default:
		return "unknown"
	}
}

// SeedSpec is an ALLOW-LIST entry. A file that is not named here is not read,
// not copied and not hashed. That polarity is the point: a new credential file
// appearing in the agent's config directory later is ignored by default rather
// than included by default.
type SeedSpec struct {
	// Rel is the path relative to the agent's ConfigDir.
	Rel string
	// Required means a missing file is an error rather than a skip.
	Required bool
	// Transform rewrites the bytes on the way in. StripCredentialKeys is what
	// makes settings.json and models.json safe to seed despite carrying keys.
	Transform Transform
}

// Image references must be fully qualified. Podman does not fall back to Docker
// Hub for an unqualified name the way Docker does: it resolves the name against
// the host's unqualified-search-registries list, which varies per machine (and
// is unset here). An unqualified reference therefore means a different image on
// a different host. Every reference this tool emits names its registry, so the
// reference resolves to the same image everywhere.
const (
	// LocalRegistry is the registry host podman assigns to images built locally.
	LocalRegistry = "localhost"
	// ImageRepository is the namespace shared by every image this tool builds.
	ImageRepository = LocalRegistry + "/agentbox"
)

// DefaultImage returns the fully-qualified reference of the image built for the
// named target (base, opencode, pi, shell).
func DefaultImage(target string) string {
	return ImageRepository + "/" + target + ":latest"
}

// Definition is one agent's declared facts.
type Definition struct {
	Name string
	// Image is a fully-qualified image name (see the image-reference constants
	// above), never a short name.
	Image   string
	Command []string

	Strategy Strategy

	// ConfigDir is the host directory to read configuration from. Empty for
	// StrategyNone.
	ConfigDir string
	// ConfigDirInContainer is where that configuration is exposed.
	ConfigDirInContainer string

	// SeedFiles is the allow-list, used by StrategySeed.
	SeedFiles []SeedSpec

	// SymlinkTargetPrefixes bounds where a followed symlink may point, by real
	// path. Used by StrategyMount.
	SymlinkTargetPrefixes []string

	// DeniedNames are filename patterns that are never mounted out of
	// ConfigDir by StrategyMount, even though their directory is.
	DeniedNames []string

	// BaseEnv is wiring the sandbox always sets (HOME, XDG_*, PI_*). These are
	// not credentials.
	BaseEnv map[string]string
	// PassthroughEnv names are copied from the host when set, so terminals and
	// locales work. Not credentials.
	PassthroughEnv []string
	// EnvAllowlist names may cross only when explicitly requested with --env.
	// Nothing else is ever read from the host environment.
	EnvAllowlist []string

	// StateDirs are created 0700 inside the ephemeral HOME.
	//
	// They are created by the session before the container starts, on the host
	// side of the HOME bind mount, so that they are owned by the invoking user
	// and are writable under --userns=keep-id. Creating them in the entrypoint
	// instead does not work: podman creates a --tmpfs owned by container 0 with
	// mode 0700, and rejects uid=/gid= on --tmpfs, so a keep-id user cannot
	// write to its own HOME at all.
	StateDirs []string
}

// Registry resolves agent names to definitions.
type Registry struct {
	defs map[string]Definition
}

func New(home string) *Registry {
	r := &Registry{defs: map[string]Definition{}}
	for _, d := range []Definition{opencodeDef(home), piDef(home), shellDef()} {
		r.defs[d.Name] = d
	}
	return r
}

func (r *Registry) Get(name string) (Definition, error) {
	if name == "" {
		return Definition{}, fmt.Errorf("no agent selected")
	}
	d, ok := r.defs[name]
	if !ok {
		return Definition{}, fmt.Errorf("unknown agent %q (known: %s)", name, strings.Join(r.Names(), ", "))
	}
	return d, nil
}

func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.defs))
	for n := range r.defs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// WithoutUserConfig returns the definition with all host-config facts removed.
// The result is a definition the same policy code handles; there is no separate
// isolated code path that could drift from the default one.
func (r *Registry) WithoutUserConfig(name string) (Definition, error) {
	d, err := r.Get(name)
	if err != nil {
		return Definition{}, err
	}
	d.Strategy = StrategyNone
	d.ConfigDir = ""
	d.SeedFiles = nil
	d.SymlinkTargetPrefixes = nil
	d.DeniedNames = nil
	d.BaseEnv = copyEnv(d.BaseEnv)
	if env := d.ConfigDirEnvVar(); env != "" {
		d.BaseEnv[env] = d.ConfigDirInContainer
	}
	return d, nil
}

// ConfigDirEnvVar is the environment variable that points the agent at its
// configuration directory.
func (d Definition) ConfigDirEnvVar() string {
	switch d.Name {
	case "opencode":
		return "OPENCODE_CONFIG_DIR"
	case "pi":
		return "PI_CODING_AGENT_DIR"
	default:
		return ""
	}
}

func copyEnv(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}
