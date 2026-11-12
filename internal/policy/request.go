package policy

// Request is the caller's literal intent. Everything here is untrusted input:
// it is what the user typed, or what a project configuration file asked for.
// policy turns it into a ResolvedSpec or refuses.
type Request struct {
	AgentName    string
	NoUserConfig bool

	// LaunchDir is the project directory. Empty means the current directory.
	LaunchDir string
	// WorkdirOverride replaces LaunchDir when set (--workdir).
	WorkdirOverride string

	// WorkspaceOverride mounts this subdirectory as the workspace instead of the
	// launch directory. A relative path is resolved against the launch
	// directory and it is validated exactly like a launch directory.
	WorkspaceOverride string
	// ReadOnlyWorkspace mounts the workspace read-only.
	ReadOnlyWorkspace bool

	// ExtraMounts are raw "SRC:DST[:ro|rw]" strings from --mount.
	ExtraMounts []string

	// EnvNames are host environment variable names requested with --env. Only
	// names on the agent's allowlist may cross, and only as NAME=VALUE.
	EnvNames []string

	// NetworkMode is "" for the policy default.
	NetworkMode string
	Memory      string
	CPUs        string
	PidsLimit   int

	// Command is the trailing pass-through argv. When empty the agent's default
	// command, or a shell, is used.
	Command []string
	// Image overrides the agent image.
	Image string
	// Hostname overrides the container hostname (--hostname). Empty means the
	// default derived from the agent name.
	Hostname string
}
