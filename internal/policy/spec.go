package policy

import "os"

// Access is a bind mount's writability.
type Access uint8

const (
	RO Access = iota
	RW
)

func (a Access) String() string {
	if a == RW {
		return "rw"
	}
	return "ro"
}

// ResolvedMount is a bind mount whose host path has been resolved and validated.
type ResolvedMount struct {
	Host   string
	Dest   string
	Access Access
	Origin string // launch-dir | agent-config | symlink | extra
}

// EnvPair is one NAME=VALUE that will be set inside the container. The value is
// never rendered into diagnostics.
type EnvPair struct {
	Name  string
	Value string
}

// NetworkDecision records the chosen network mode and any warning attached.
type NetworkDecision struct {
	Mode    string
	Warning string
}

// SeededFile is one allow-listed config file that will be copied in.
type SeededFile struct {
	Rel         string
	Size        int
	Mode        os.FileMode
	SHA256      string
	Transform   string
	RemovedKeys []string
	Data        []byte
}

// Limits are resource caps.
type Limits struct {
	Memory string
	CPUs   string
	Pids   int
}

// ResolvedSpec is the single, fully-decided artifact for a run. It is consumed
// by the argv renderer, by doctor, by --print-argv and by the audit log, so
// those four can never disagree about what was decided.
type ResolvedSpec struct {
	Agent      string
	Image      string
	Command    []string
	Workdir    string
	UserConfig bool

	// Hostname is the container hostname: gethostname(2) and /etc/hostname
	// inside the sandbox. Always set — the default is derived from the agent
	// name — so the agent can tell which box it is in.
	Hostname string

	Mounts  []ResolvedMount
	Env     []EnvPair
	Tmpfs   []string
	Seed    []SeededFile
	Network NetworkDecision

	// WritableStateDirs are created 0700 by the entrypoint. Bare tmpfs is 1777
	// and podman rejects uid=/gid= on --tmpfs, so the entrypoint is the only
	// place this can be fixed.
	WritableStateDirs []string

	// Hardening. These are constants of the design, not options.
	Userns          string
	CapDrop         bool
	NoNewPrivileges bool
	ReadOnly        bool
	UnsetEnv        bool
	HTTPProxy       bool

	Limits Limits

	// Refusals records every denial, fatal or not, for audit.
	Refusals []Refusal
}
