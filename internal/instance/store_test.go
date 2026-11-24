package instance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/agent"
	"agentbox/internal/config"
	"agentbox/internal/fsx"
	"agentbox/internal/instance"
	"agentbox/internal/policy"
)

func newStore(t *testing.T) *instance.Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instance.DirEnv, dir)
	store, err := instance.OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testConfig() config.File {
	userConfig := true
	return config.File{
		Agent:      "opencode",
		Image:      "localhost/agentbox/opencode:latest",
		Workdir:    "/work",
		Env:        []string{"OPENCODE_API_KEY"},
		Mounts:     []string{"/tmp:/mnt:ro"},
		Workspace:  "should-be-cleared",
		UserConfig: &userConfig,
	}
}

func TestCreateLoadListRemove(t *testing.T) {
	store := newStore(t)
	inst, err := store.Create("dev", testConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Name != "dev" || inst.ContainerName() != "agentbox-dev" {
		t.Fatalf("unexpected instance: %+v", inst)
	}
	if inst.Config.Workspace != "" {
		t.Fatalf("workspace must not be stored, got %q", inst.Config.Workspace)
	}
	if inst.Meta.Schema != instance.Schema || !inst.Meta.PersistState {
		t.Fatalf("unexpected metadata: %+v", inst.Meta)
	}
	for _, dir := range []string{inst.Dir, inst.ConfigRoot(), inst.Home()} {
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %04o, want 0700", dir, fi.Mode().Perm())
		}
	}

	loaded, err := store.Load("dev")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Config.Agent != "opencode" || loaded.Config.Workdir != "/work" {
		t.Fatalf("config not round-tripped: %+v", loaded.Config)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "dev" || entries[0].Err != nil {
		t.Fatalf("unexpected list: %+v", entries)
	}

	if err := store.Remove("dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("dev"); !os.IsNotExist(err) {
		t.Fatalf("Load after Remove = %v, want not-exist", err)
	}
}

func TestCreateDuplicateAndInvalidName(t *testing.T) {
	store := newStore(t)
	if _, err := store.Create("dev", testConfig(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("dev", testConfig(), false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate create = %v", err)
	}
	for _, name := range []string{"", "Dev", "../x", "a/b", "-x", strings.Repeat("a", 33)} {
		if _, err := store.Create(name, testConfig(), false); err == nil {
			t.Fatalf("Create(%q) should fail", name)
		}
	}
}

func TestCreateWithoutPersistentHome(t *testing.T) {
	store := newStore(t)
	inst, err := store.Create("ephemeral", testConfig(), false)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Meta.PersistState {
		t.Fatal("persist state should be false")
	}
	if _, err := os.Lstat(inst.Home()); !os.IsNotExist(err) {
		t.Fatalf("home should not exist, got %v", err)
	}
	if _, err := store.Load("ephemeral"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsTamperedInstance(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(t *testing.T, inst *instance.Instance)
	}{
		{
			name: "directory mode",
			tamper: func(t *testing.T, inst *instance.Instance) {
				if err := os.Chmod(inst.Dir, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "config directory symlink",
			tamper: func(t *testing.T, inst *instance.Instance) {
				if err := os.RemoveAll(inst.ConfigRoot()); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), inst.ConfigRoot()); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing home",
			tamper: func(t *testing.T, inst *instance.Instance) {
				if err := os.RemoveAll(inst.Home()); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "metadata mode",
			tamper: func(t *testing.T, inst *instance.Instance) {
				if err := os.Chmod(filepath.Join(inst.Dir, "instance.yaml"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown metadata key",
			tamper: func(t *testing.T, inst *instance.Instance) {
				path := filepath.Join(inst.Dir, "instance.yaml")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(data, []byte("unknown: true\n")...), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "config name mismatch",
			tamper: func(t *testing.T, inst *instance.Instance) {
				path := filepath.Join(inst.Dir, "instance.yaml")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data = []byte(strings.Replace(string(data), "name: dev", "name: other", 1))
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown config key",
			tamper: func(t *testing.T, inst *instance.Instance) {
				path := filepath.Join(inst.Dir, "config.yaml")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(data, []byte("unknown: true\n")...), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore(t)
			inst, err := store.Create("dev", testConfig(), true)
			if err != nil {
				t.Fatal(err)
			}
			tc.tamper(t, inst)
			if _, err := store.Load("dev"); err == nil {
				t.Fatal("Load should reject the tampered instance")
			}
		})
	}
}

func TestLoadRejectsSymlinkedInstanceDirectory(t *testing.T) {
	store := newStore(t)
	inst, err := store.Create("real", testConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inst.Dir, filepath.Join(store.Root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("link"); err == nil {
		t.Fatal("a symlinked instance directory must be refused")
	}
}

func TestListSkipsDotDirectoriesAndReportsInvalid(t *testing.T) {
	store := newStore(t)
	if _, err := store.Create("good", testConfig(), true); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(store.Root, ".tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(store.Root, "broken"), 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name != "broken" || entries[0].Err == nil || entries[1].Name != "good" {
		t.Fatalf("unexpected list: %+v", entries)
	}
}

func TestRemoveRefusesSymlinkedDirectory(t *testing.T) {
	store := newStore(t)
	inst, err := store.Create("real", testConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inst.Dir, filepath.Join(store.Root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("link"); err == nil {
		t.Fatal("Remove must refuse a symlinked instance directory")
	}
	if _, err := os.Stat(inst.Dir); err != nil {
		t.Fatalf("real instance should still exist: %v", err)
	}
}

func TestOpenStoreRejectsInsecureRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instance.DirEnv, dir)
	if _, err := instance.OpenStore(); err == nil {
		t.Fatal("OpenStore should reject a group/world-accessible root")
	}
}

func TestOpenStoreRejectsSymlinkedRoot(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instance.DirEnv, link)
	store, err := instance.OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	if store.Root != real {
		t.Fatalf("OpenStore root = %s, want resolved %s", store.Root, real)
	}
}

func mountDefinition(host string) agent.Definition {
	return agent.Definition{
		Name:                  "test",
		Strategy:              agent.StrategyMount,
		ConfigDir:             host,
		ConfigDirInContainer:  "/home/agent/.config/test",
		DeniedNames:           []string{"secret*"},
		SymlinkTargetPrefixes: []string{host},
	}
}

func TestCloneConfigSanitizesAndSkips(t *testing.T) {
	store := newStore(t)
	inst, err := store.Create("dev", testConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	if err := os.WriteFile(filepath.Join(host, "settings.json"), []byte(`{"theme":"dark","apiKey":"sk-live"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, "notes.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, "secret.txt"), []byte("no"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(host, "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, "skills", "a.md"), []byte("skill"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, "skills", "secret.txt"), []byte("nested no"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(host, "nested-link")); err != nil {
		t.Fatal(err)
	}

	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	warnings, err := store.CloneConfig(inst, mountDefinition(host), resolver, false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "secret.txt") {
		t.Fatalf("warnings should name the denied file: %s", joined)
	}
	if _, err := os.Stat(filepath.Join(inst.ConfigRoot(), "secret.txt")); !os.IsNotExist(err) {
		t.Fatalf("denied file should not be cloned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(inst.ConfigRoot(), "nested-link")); !os.IsNotExist(err) {
		t.Fatalf("nested symlink should not be cloned: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(inst.ConfigRoot(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sk-live") || !strings.Contains(string(data), "dark") {
		t.Fatalf("credential key not stripped: %s", data)
	}
	if _, err := os.Stat(filepath.Join(inst.ConfigRoot(), "skills", "a.md")); err != nil {
		t.Fatalf("directory tree should be cloned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(inst.ConfigRoot(), "skills", "secret.txt")); !os.IsNotExist(err) {
		t.Fatalf("nested denied file should not be cloned: %v", err)
	}

	loaded, err := store.Load("dev")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Meta.Source.ConfigDir != host || len(loaded.Meta.Source.Files) == 0 {
		t.Fatalf("clone provenance not recorded: %+v", loaded.Meta.Source)
	}
}

func TestCloneConfigSeedAndStrictJSON(t *testing.T) {
	store := newStore(t)
	inst, err := store.Create("dev", testConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	if err := os.WriteFile(filepath.Join(host, "settings.json"), []byte(`{"theme":"dark","apiKeys":{"x":"sk"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	def := agent.Definition{
		Name:      "pi",
		Strategy:  agent.StrategySeed,
		ConfigDir: host,
		SeedFiles: []agent.SeedSpec{{Rel: "settings.json", Transform: agent.StripCredentialKeys{}}},
	}
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, def, resolver, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(inst.ConfigRoot(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sk") || !strings.Contains(string(data), "dark") {
		t.Fatalf("seed was not sanitized: %s", data)
	}

	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "settings.json"), []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	def.ConfigDir = bad
	if _, err := store.CloneConfig(inst, def, resolver, true); err == nil {
		t.Fatal("strict clone should fail on unsanitizable JSON")
	}
}

func TestCloneConfigFatalRefusalKeepsOldConfig(t *testing.T) {
	store := newStore(t)
	inst, err := store.Create("dev", testConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inst.ConfigRoot(), "keep.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	def := mountDefinition(filepath.Join(t.TempDir(), "missing"))
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, def, resolver, false); err == nil {
		t.Fatal("a missing config directory should be fatal")
	}
	data, err := os.ReadFile(filepath.Join(inst.ConfigRoot(), "keep.txt"))
	if err != nil || string(data) != "old" {
		t.Fatalf("old config should survive a failed clone: %q, %v", data, err)
	}
}
