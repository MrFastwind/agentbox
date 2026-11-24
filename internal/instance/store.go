// Package instance stores named, reusable agent instances.
//
// An instance is a saved profile: its own agent configuration, an optional
// persistent HOME, and the metadata needed to explain where both came from.
// Opening an instance still starts a fresh --rm sandbox; only the profile and
// HOME survive. That keeps the sandbox ephemeral while making auth and agent
// state reusable by explicit name.
package instance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"agentbox/internal/config"
	"agentbox/internal/policy"
)

// DirEnv overrides the store location. The default is under ~/.agentbox rather
// than XDG data because ~/.local is on policy's deny-list: a store there could
// not be mounted into the sandbox without weakening the rule that protects
// agent state.
const DirEnv = "AGENTBOX_INSTANCE_DIR"

// Schema is the instance metadata version understood by this binary.
const Schema = 1

const (
	configFileName   = "config.yaml"
	metadataFileName = "instance.yaml"
	configDirName    = "config"
	homeDirName      = "home"
)

// Store is a directory of instances. Root is already resolved (no symlinks).
type Store struct {
	Root string
}

// Instance is one loaded instance. Config is the effective stored project
// configuration; Meta records how it was cloned.
type Instance struct {
	Name   string
	Dir    string
	Config config.File
	Meta   Metadata
}

// ConfigRoot is the directory mounted as the agent's config directory.
func (i *Instance) ConfigRoot() string { return filepath.Join(i.Dir, configDirName) }

// Home is the persistent HOME path. It exists only when Meta.PersistState is
// true; callers must check that before passing it to policy.
func (i *Instance) Home() string { return filepath.Join(i.Dir, homeDirName) }

// ContainerName is the deterministic podman name for this instance. It is also
// what `agentbox exec NAME` resolves to.
func (i *Instance) ContainerName() string { return "agentbox-" + i.Name }

// Metadata is the instance.yaml schema. It is separate from config.yaml so a
// refresh can replace the cloned config without losing identity or provenance.
type Metadata struct {
	Schema       int       `yaml:"schema"`
	Name         string    `yaml:"name"`
	Created      time.Time `yaml:"created"`
	PersistState bool      `yaml:"persist_state"`
	Source       Source    `yaml:"source,omitempty"`
}

// Source records the host configuration a clone came from. It is diagnostic,
// not authoritative: open always reads the cloned files, never these paths.
type Source struct {
	ConfigDir string          `yaml:"config_dir,omitempty"`
	ClonedAt  time.Time       `yaml:"cloned_at,omitempty"`
	Files     []ManifestEntry `yaml:"files,omitempty"`
}

// ManifestEntry is one cloned file. RemovedKeys names credential-shaped JSON
// keys that were stripped; it never carries values.
type ManifestEntry struct {
	Rel         string   `yaml:"rel"`
	Size        int      `yaml:"size"`
	SHA256      string   `yaml:"sha256"`
	Transform   string   `yaml:"transform,omitempty"`
	RemovedKeys []string `yaml:"removed_keys,omitempty"`
	Origin      string   `yaml:"origin,omitempty"`
}

// Entry is one result from List. Err is set for a directory that looks like an
// instance but cannot be loaded; listing the rest is more useful than failing
// the whole command.
type Entry struct {
	Name     string
	Instance *Instance
	Err      error
}

// OpenStore opens (and creates if needed) the instance store. The root is
// resolved before validation so every later path comparison is against the
// real directory, not a user-controlled symlink.
func OpenStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("finding home directory: %w", err)
	}
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return nil, fmt.Errorf("resolving home directory: %w", err)
	}

	root := os.Getenv(DirEnv)
	if root == "" {
		root = filepath.Join(home, ".agentbox", "instances")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving instance store: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("creating instance store: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolving instance store: %w", err)
	}
	if err := policy.ValidateInstanceRoot(resolvedHome, real); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(real)
	if err != nil {
		return nil, fmt.Errorf("checking instance store: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("instance store %s is not a directory", real)
	}
	if fi.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("instance store %s has mode %04o; must be 0700", real, fi.Mode().Perm())
	}
	return &Store{Root: real}, nil
}

// Create reserves a new instance directory. The directory itself is the
// reservation, so two concurrent creates cannot silently share a name.
func (s *Store) Create(name string, cfg config.File, persist bool) (*Instance, error) {
	if s.Root == "" {
		return nil, fmt.Errorf("instance store root is empty")
	}
	if err := policy.ValidateInstanceName(name); err != nil {
		return nil, err
	}
	dir := filepath.Join(s.Root, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("instance %q already exists", name)
		}
		return nil, fmt.Errorf("creating instance: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(dir)
		}
	}()

	if err := os.Mkdir(filepath.Join(dir, configDirName), 0o700); err != nil {
		return nil, fmt.Errorf("creating instance config directory: %w", err)
	}
	if persist {
		if err := os.Mkdir(filepath.Join(dir, homeDirName), 0o700); err != nil {
			return nil, fmt.Errorf("creating instance home: %w", err)
		}
	}

	// The workspace is deliberately per-open, never stored: an instance is a
	// profile, not a binding to one project directory.
	cfg.Workspace = ""
	meta := Metadata{
		Schema:       Schema,
		Name:         name,
		Created:      time.Now().UTC(),
		PersistState: persist,
	}

	if err := writeYAML(filepath.Join(dir, configFileName), cfg); err != nil {
		return nil, err
	}
	if err := writeYAML(filepath.Join(dir, metadataFileName), meta); err != nil {
		return nil, err
	}
	cleanup = false
	return s.Load(name)
}

// Load reads and validates one instance. Validation is repeated here rather
// than trusted from Create because instance files are on a durable writable
// surface: a later sandbox run could have edited them.
func (s *Store) Load(name string) (*Instance, error) {
	if err := policy.ValidateInstanceName(name); err != nil {
		return nil, err
	}
	dir := filepath.Join(s.Root, name)
	if filepath.Dir(dir) != s.Root {
		return nil, fmt.Errorf("instance path escapes the store")
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("instance %q is not a real directory", name)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	if real != dir {
		return nil, fmt.Errorf("instance %q resolves to %s; refusing a symlinked instance", name, real)
	}
	if fi.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("instance %q has mode %04o; must be 0700", name, fi.Mode().Perm())
	}

	meta, err := loadMetadata(filepath.Join(dir, metadataFileName))
	if err != nil {
		return nil, err
	}
	if meta.Schema != Schema {
		return nil, fmt.Errorf("instance %q has unsupported schema %d", name, meta.Schema)
	}
	if meta.Name != name {
		return nil, fmt.Errorf("instance %q names itself %q", name, meta.Name)
	}

	cfgFile, err := os.Open(filepath.Join(dir, configFileName))
	if err != nil {
		return nil, fmt.Errorf("opening instance config: %w", err)
	}
	defer cfgFile.Close()
	cfg, err := config.Decode(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("parsing instance config: %w", err)
	}
	if err := checkDir(filepath.Join(dir, configDirName)); err != nil {
		return nil, err
	}
	if meta.PersistState {
		if err := checkDir(filepath.Join(dir, homeDirName)); err != nil {
			return nil, err
		}
	}
	for _, file := range []string{configFileName, metadataFileName} {
		fi, err := os.Lstat(filepath.Join(dir, file))
		if err != nil {
			return nil, err
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("instance %q file %s must not be group- or world-accessible", name, file)
		}
	}

	return &Instance{Name: name, Dir: dir, Config: *cfg, Meta: meta}, nil
}

// List returns every valid-looking instance, sorted by name. Dot-directories
// are skipped so a partially-created or backup directory is not reported as an
// instance.
func (s *Store) List() ([]Entry, error) {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		inst, err := s.Load(entry.Name())
		out = append(out, Entry{Name: entry.Name(), Instance: inst, Err: err})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Remove deletes an instance directory and its HOME. The path is re-checked so
// a tampered instance.yaml cannot turn a name into an arbitrary RemoveAll.
func (s *Store) Remove(name string) error {
	if err := policy.ValidateInstanceName(name); err != nil {
		return err
	}
	dir := filepath.Join(s.Root, name)
	if filepath.Dir(dir) != s.Root {
		return fmt.Errorf("instance path escapes the store")
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove %s: not a real instance directory", dir)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	if real != dir {
		return fmt.Errorf("refusing to remove %s: resolves to %s", dir, real)
	}
	return os.RemoveAll(dir)
}

func loadMetadata(path string) (Metadata, error) {
	f, err := os.Open(path)
	if err != nil {
		return Metadata{}, fmt.Errorf("opening instance metadata: %w", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var meta Metadata
	if err := dec.Decode(&meta); err != nil {
		return Metadata{}, fmt.Errorf("parsing instance metadata: %w", err)
	}
	return meta, nil
}

func checkDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real directory", path)
	}
	if fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s has mode %04o; must be 0700", path, fi.Mode().Perm())
	}
	return nil
}

func writeYAML(path string, value any) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return fmt.Errorf("encoding %s: %w", filepath.Base(path), err)
	}
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
