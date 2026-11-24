package update

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"agentbox/internal/policy"
)

const stateFile = "images.yaml"

// ErrLegacyState reports a v1 state file recorded before the musl/scratch image
// migration. Those records describe glibc images that must not be launched with
// the new runtime wiring, so they are discarded rather than silently reused.
var ErrLegacyState = errors.New("image state predates musl images")

// State records which exact image this machine last installed for each agent.
// Runs use that pin instead of silently following a rebuilt :latest tag.
type State struct {
	Version int                 `yaml:"version"`
	Agents  map[string]Record   `yaml:"agents"`
	History map[string][]Record `yaml:"history,omitempty"`
}

// Record is an installed image and the inputs needed to rebuild it offline.
type Record struct {
	Version   string            `yaml:"version"`
	Image     string            `yaml:"image"`
	Args      map[string]string `yaml:"args"`
	Source    string            `yaml:"source,omitempty"`
	UpdatedAt string            `yaml:"updated_at,omitempty"`
}

// StatePath returns the per-user state file, honouring XDG_STATE_HOME and an
// explicit test override.
func StatePath() (string, error) {
	if dir := os.Getenv("AGENTBOX_STATE_DIR"); dir != "" {
		return filepath.Join(dir, stateFile), nil
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locating home directory: %w", err)
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "agentbox", stateFile), nil
}

// LoadState reads local image state. A missing file is an empty state, not an
// error: a binary works before its first explicit update.
func LoadState() (*State, error) {
	path, err := StatePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return newState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading image state: %w", err)
	}
	var state State
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&state); err != nil {
		return nil, fmt.Errorf("parsing image state: %w", err)
	}
	if state.Version == 1 {
		return nil, fmt.Errorf("%w: run agentbox images update", ErrLegacyState)
	}
	if state.Version != 2 {
		return nil, fmt.Errorf("unsupported image state version %d", state.Version)
	}
	if state.Agents == nil {
		state.Agents = map[string]Record{}
	}
	if state.History == nil {
		state.History = map[string][]Record{}
	}
	return &state, nil
}

func newState() *State {
	return &State{Version: 2, Agents: map[string]Record{}, History: map[string][]Record{}}
}

// NewState returns an empty state at the current schema version. Callers that
// recover from ErrLegacyState use it instead of keeping unusable glibc records.
func NewState() *State {
	return newState()
}

// SaveState writes image state atomically with private permissions.
func SaveState(state *State) error {
	if state == nil {
		return fmt.Errorf("image state is nil")
	}
	state.Version = 2
	path, err := StatePath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating image state directory: %w", err)
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return fmt.Errorf("encoding image state: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".images-*")
	if err != nil {
		return fmt.Errorf("creating temporary image state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("securing temporary image state: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temporary image state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temporary image state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("installing image state: %w", err)
	}
	return nil
}

// For returns a copy of an installed record.
func (s *State) For(agent string) (Record, bool) {
	if s == nil {
		return Record{}, false
	}
	rec, ok := s.Agents[agent]
	if !ok {
		return Record{}, false
	}
	rec.Args = copyArgs(rec.Args)
	return rec, true
}

// Set installs a record, appending the previous record to history.
func (s *State) Set(agent string, rec Record) error {
	if s == nil {
		return fmt.Errorf("image state is nil")
	}
	if err := policy.ValidateAgentVersion(rec.Version); err != nil {
		return fmt.Errorf("agent %s: %w", agent, err)
	}
	if err := policy.ValidateImageRef(rec.Image); err != nil {
		return fmt.Errorf("agent %s image: %w", agent, err)
	}
	if s.Agents == nil {
		s.Agents = map[string]Record{}
	}
	if s.History == nil {
		s.History = map[string][]Record{}
	}
	if old, ok := s.Agents[agent]; ok && old.Version != rec.Version {
		s.History[agent] = append(s.History[agent], old)
	}
	rec.Args = copyArgs(rec.Args)
	s.Agents[agent] = rec
	return nil
}

// Historical returns the recorded image with the given version, if any.
func (s *State) Historical(agent, version string) (Record, bool) {
	if s == nil {
		return Record{}, false
	}
	for _, rec := range s.History[agent] {
		if rec.Version == version {
			rec.Args = copyArgs(rec.Args)
			return rec, true
		}
	}
	return Record{}, false
}

// ImageRef is the immutable, fully-qualified tag produced by an update.
func ImageRef(agent, version string) string {
	return "localhost/agentbox/" + agent + ":" + version
}

// LatestRef is the moving compatibility tag produced by every build.
func LatestRef(agent string) string {
	return "localhost/agentbox/" + agent + ":latest"
}

// Timestamp is the format used in state records. It is a function so tests can
// assert a stable shape without depending on the clock.
func Timestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// RecordFor builds the state record for a resolved pin.
func RecordFor(agent string, pin AgentPin, image string) Record {
	return Record{
		Version:   pin.Version,
		Image:     image,
		Args:      copyArgs(pin.Args),
		Source:    pin.Source,
		UpdatedAt: Timestamp(),
	}
}

func copyArgs(args map[string]string) map[string]string {
	out := make(map[string]string, len(args))
	for k, v := range args {
		out[k] = v
	}
	return out
}
