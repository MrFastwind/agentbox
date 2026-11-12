// Package audit writes a durable record of what was decided.
//
// doctor and --print-argv are transient and human-only. Because the seeded-file
// boundary for agents that keep configuration and credentials together is a
// file-level allow-list, the boundary has to be auditable after the fact, not
// merely asserted. This is that artifact.
package audit

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	"agentbox/internal/policy"
)

// Record is one run's decisions.
type Record struct {
	Agent       string        `json:"agent"`
	Image       string        `json:"image"`
	Hostname    string        `json:"hostname"`
	UserConfig  bool          `json:"user_config"`
	Network     string        `json:"network"`
	NetworkNote string        `json:"network_note,omitempty"`
	Userns      string        `json:"userns"`
	CapDrop     bool          `json:"cap_drop_all"`
	ReadOnly    bool          `json:"read_only"`
	UnsetEnv    bool          `json:"unsetenv_all"`
	HTTPProxy   bool          `json:"http_proxy"`
	Limits      Limits        `json:"limits"`
	Mounts      []MountRecord `json:"mounts"`
	EnvNames    []string      `json:"env_names"`
	Seeded      []SeedRecord  `json:"seeded_files"`
	Tmpfs       []string      `json:"tmpfs"`
	StateDirs   []string      `json:"state_dirs"`
	Refusals    []string      `json:"refusals,omitempty"`
	Argv        []string      `json:"argv"`
}

type Limits struct {
	Memory string `json:"memory"`
	CPUs   string `json:"cpus"`
	Pids   int    `json:"pids"`
}

type MountRecord struct {
	Host   string `json:"host"`
	Dest   string `json:"dest"`
	Access string `json:"access"`
	Origin string `json:"origin"`
}

type SeedRecord struct {
	Rel         string   `json:"rel"`
	Size        int      `json:"size"`
	SHA256      string   `json:"sha256"`
	Transform   string   `json:"transform"`
	RemovedKeys []string `json:"removed_keys,omitempty"`
}

// Logger writes newline-delimited JSON records.
type Logger struct {
	w io.Writer
}

func New(w io.Writer) *Logger { return &Logger{w: w} }

func (l *Logger) Record(spec *policy.ResolvedSpec, argv []string) error {
	rec := Record{
		Agent:       spec.Agent,
		Image:       spec.Image,
		Hostname:    spec.Hostname,
		UserConfig:  spec.UserConfig,
		Network:     spec.Network.Mode,
		NetworkNote: spec.Network.Warning,
		Userns:      spec.Userns,
		CapDrop:     spec.CapDrop,
		ReadOnly:    spec.ReadOnly,
		UnsetEnv:    spec.UnsetEnv,
		HTTPProxy:   spec.HTTPProxy,
		Limits: Limits{
			Memory: spec.Limits.Memory,
			CPUs:   spec.Limits.CPUs,
			Pids:   spec.Limits.Pids,
		},
		Tmpfs:     spec.Tmpfs,
		StateDirs: spec.WritableStateDirs,
		Argv:      RedactArgv(argv),
	}

	for _, m := range spec.Mounts {
		rec.Mounts = append(rec.Mounts, MountRecord{
			Host: m.Host, Dest: m.Dest, Access: m.Access.String(), Origin: m.Origin,
		})
	}
	for _, e := range spec.Env {
		rec.EnvNames = append(rec.EnvNames, e.Name)
	}
	sort.Strings(rec.EnvNames)
	for _, s := range spec.Seed {
		rec.Seeded = append(rec.Seeded, SeedRecord{
			Rel: s.Rel, Size: s.Size, SHA256: s.SHA256,
			Transform: s.Transform, RemovedKeys: s.RemovedKeys,
		})
	}
	for _, r := range spec.Refusals {
		rec.Refusals = append(rec.Refusals, r.String())
	}

	enc := json.NewEncoder(l.w)
	return enc.Encode(rec)
}

// RedactArgv removes environment *values* from a rendered argv, keeping names.
// An environment variable is a capability; it does not belong in a log file.
func RedactArgv(argv []string) []string {
	out := make([]string, len(argv))
	copy(out, argv)
	for i := 0; i+1 < len(out); i++ {
		if out[i] == "--env" {
			if eq := strings.IndexByte(out[i+1], '='); eq >= 0 {
				out[i+1] = out[i+1][:eq] + "=***"
			}
		}
	}
	return out
}
