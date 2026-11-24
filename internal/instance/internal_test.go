package instance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"agentbox/internal/agent"
	"agentbox/internal/config"
	"agentbox/internal/fsx"
	"agentbox/internal/policy"
)

func internalStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(DirEnv, dir)
	store, err := OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func internalConfig() config.File {
	userConfig := true
	return config.File{Agent: "opencode", Workspace: "ignored", UserConfig: &userConfig}
}

func internalMountDefinition(host string) agent.Definition {
	return agent.Definition{
		Name: "test", Strategy: agent.StrategyMount, ConfigDir: host,
		ConfigDirInContainer: "/home/agent/.config/test",
	}
}

func TestCopyPathSkipsSymlinkAndSpecialFile(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(src, "a.txt"), filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(src, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	var warnings []string
	var manifest []ManifestEntry
	if err := copyPath(src, dst, "root", "test", nil, false, &cloneBudget{}, &warnings, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 1 || manifest[0].Rel != "root/a.txt" {
		t.Fatalf("manifest = %+v", manifest)
	}
	if _, err := os.Stat(filepath.Join(dst, "link")); !os.IsNotExist(err) {
		t.Fatalf("symlink should be skipped: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "fifo")); !os.IsNotExist(err) {
		t.Fatalf("fifo should be skipped: %v", err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "symlink") || !strings.Contains(joined, "not a regular file") {
		t.Fatalf("warnings = %q", joined)
	}
}

func TestCopyPathInvalidJSON(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "bad.json"), []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	var warnings []string
	var manifest []ManifestEntry
	if err := copyPath(src, filepath.Join(t.TempDir(), "out"), "root", "test", nil, false, &cloneBudget{}, &warnings, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 0 || len(warnings) == 0 {
		t.Fatalf("invalid JSON should be skipped with a warning: manifest=%+v warnings=%v", manifest, warnings)
	}
	if err := copyPath(src, filepath.Join(t.TempDir(), "out"), "root", "test", nil, true, &cloneBudget{}, &warnings, &manifest); err == nil {
		t.Fatal("strict copy should fail on invalid JSON")
	}
}

func TestCopyPathWriteFailure(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := os.Mkdir(filepath.Join(dst, "a.txt"), 0o700); err != nil {
		t.Fatal(err)
	}
	var warnings []string
	var manifest []ManifestEntry
	if err := copyPath(filepath.Join(src, "a.txt"), filepath.Join(dst, "a.txt"), "a.txt", "test", nil, false, &cloneBudget{}, &warnings, &manifest); err == nil {
		t.Fatal("writing over a directory should fail")
	}
}

func TestCloneBudgetLimits(t *testing.T) {
	b := &cloneBudget{}
	if err := b.add(maxCloneBytes + 1); err == nil {
		t.Fatal("byte budget should fail")
	}
	b = &cloneBudget{}
	for i := 0; i < maxCloneFiles; i++ {
		if err := b.add(0); err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
	}
	if err := b.add(0); err == nil {
		t.Fatal("file budget should fail")
	}
}

func TestWriteAtomicFailure(t *testing.T) {
	if err := writeFileAtomic(filepath.Join(t.TempDir(), "missing", "x"), []byte("x"), 0o600); err == nil {
		t.Fatal("writing into a missing directory should fail")
	}
}

func TestOpenStoreRejectsFileRoot(t *testing.T) {
	file := filepath.Join(t.TempDir(), "root")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(DirEnv, file)
	if _, err := OpenStore(); err == nil {
		t.Fatal("a file root should be refused")
	}
}

func TestOpenStoreRejectsFilesystemRoot(t *testing.T) {
	t.Setenv(DirEnv, "/")
	if _, err := OpenStore(); err == nil {
		t.Fatal("the filesystem root should be refused")
	}
}

func TestRemoveMissingAndNonDirectory(t *testing.T) {
	store := internalStore(t)
	if err := store.Remove("missing"); err != nil {
		t.Fatalf("removing a missing instance should be idempotent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.Root, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("file"); err == nil {
		t.Fatal("removing a non-directory should fail")
	}
}

func TestLoadMissingPartsAndSchema(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(inst.Dir, "instance.yaml")
	raw, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meta, []byte(strings.Replace(string(raw), "schema: 1", "schema: 99", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("dev"); err == nil {
		t.Fatal("unsupported schema should fail")
	}
	if err := os.WriteFile(meta, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(inst.Dir, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("dev"); err == nil {
		t.Fatal("missing config.yaml should fail")
	}
}

func TestLoadMissingConfigDirectory(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(inst.ConfigRoot()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("dev"); err == nil {
		t.Fatal("missing config directory should fail")
	}
}

func TestCloneConfigRefusesTamperedConfigDirectory(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(inst.ConfigRoot()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), inst.ConfigRoot()); err != nil {
		t.Fatal(err)
	}
	def := internalMountDefinition(t.TempDir())
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, def, resolver, false); err == nil {
		t.Fatal("a symlinked config directory must be refused")
	}
}

func TestCloneConfigInvalidJSONNonStrict(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	if err := os.WriteFile(filepath.Join(host, "bad.json"), []byte(`{bad`), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	warnings, err := store.CloneConfig(inst, internalMountDefinition(host), resolver, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) == 0 {
		t.Fatal("invalid JSON should produce a warning")
	}
	if _, err := os.Stat(filepath.Join(inst.ConfigRoot(), "bad.json")); !os.IsNotExist(err) {
		t.Fatalf("invalid JSON should not be cloned: %v", err)
	}
}

func TestCloneConfigSeedMissingRequired(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	def := agent.Definition{
		Name:      "pi",
		Strategy:  agent.StrategySeed,
		ConfigDir: t.TempDir(),
		SeedFiles: []agent.SeedSpec{{Rel: "settings.json", Required: true, Transform: agent.Identity{}}},
	}
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, def, resolver, false); err == nil {
		t.Fatal("a missing required seed should fail")
	}
}

func TestLoadNonDirectory(t *testing.T) {
	store := internalStore(t)
	if err := os.WriteFile(filepath.Join(store.Root, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("file"); err == nil {
		t.Fatal("a file is not an instance")
	}
}

func TestListReadDirError(t *testing.T) {
	store := &Store{Root: filepath.Join(t.TempDir(), "missing")}
	if _, err := store.List(); err == nil {
		t.Fatal("missing store root should fail")
	}
}

func TestRemoveInvalidName(t *testing.T) {
	store := internalStore(t)
	if err := store.Remove("../x"); err == nil {
		t.Fatal("invalid name should fail")
	}
}

func TestCheckDirMissing(t *testing.T) {
	if err := checkDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing directory should fail")
	}
}

func TestCreateRootMissing(t *testing.T) {
	store := &Store{Root: filepath.Join(t.TempDir(), "missing")}
	if _, err := store.Create("dev", internalConfig(), false); err == nil {
		t.Fatal("missing store root should fail")
	}
}

func TestOpenStoreDanglingRoot(t *testing.T) {
	parent := t.TempDir()
	link := filepath.Join(parent, "link")
	if err := os.Symlink(filepath.Join(parent, "missing"), link); err != nil {
		t.Fatal(err)
	}
	t.Setenv(DirEnv, link)
	if _, err := OpenStore(); err == nil {
		t.Fatal("a dangling store symlink should fail")
	}
}

func TestCloneConfigTmpMkdirFailure(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inst.Dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(inst.Dir, 0o700)
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, internalMountDefinition(t.TempDir()), resolver, false); err == nil {
		t.Fatal("an unwritable instance directory should fail")
	}
}

func TestCloneConfigMetadataWriteFailure(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(inst.Dir, "instance.yaml")
	if err := os.Remove(meta); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(meta, 0o700); err != nil {
		t.Fatal(err)
	}
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, internalMountDefinition(t.TempDir()), resolver, false); err == nil {
		t.Fatal("metadata write failure should be reported")
	}
}

func TestCopyPathLstatAndMkdirErrors(t *testing.T) {
	var warnings []string
	var manifest []ManifestEntry
	if err := copyPath(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "out"), "x", "test", nil, false, &cloneBudget{}, &warnings, &manifest); err == nil {
		t.Fatal("missing source should fail")
	}
	src := t.TempDir()
	dst := t.TempDir()
	if err := copyPath(src, dst, "x", "test", nil, false, &cloneBudget{}, &warnings, &manifest); err == nil {
		t.Fatal("existing destination should fail")
	}
}

func TestCopyPathReadErrors(t *testing.T) {
	var warnings []string
	var manifest []ManifestEntry
	src := t.TempDir()
	sub := filepath.Join(src, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(sub, 0o700)
	if err := copyPath(src, filepath.Join(t.TempDir(), "out"), "x", "test", nil, false, &cloneBudget{}, &warnings, &manifest); err == nil {
		t.Fatal("unreadable directory should fail")
	}
}

func TestOpenStoreDefaultRoot(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv(DirEnv, "")
	store, err := OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".agentbox", "instances")
	if store.Root != want {
		t.Fatalf("default root = %s, want %s", store.Root, want)
	}
}

func TestOpenStoreHomeErrors(t *testing.T) {
	t.Run("empty home", func(t *testing.T) {
		t.Setenv("HOME", "")
		t.Setenv(DirEnv, "")
		if _, err := OpenStore(); err == nil {
			t.Fatal("an empty HOME should fail")
		}
	})
	t.Run("missing home", func(t *testing.T) {
		t.Setenv("HOME", filepath.Join(t.TempDir(), "missing"))
		t.Setenv(DirEnv, "")
		if _, err := OpenStore(); err == nil {
			t.Fatal("a missing HOME should fail")
		}
	})
}

func TestLoadInvalidName(t *testing.T) {
	store := internalStore(t)
	if _, err := store.Load("../x"); err == nil {
		t.Fatal("invalid name should fail")
	}
}

func TestCheckDirMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkDir(dir); err == nil {
		t.Fatal("a group/world-accessible directory should fail")
	}
}

func TestRemovePermissionError(t *testing.T) {
	store := internalStore(t)
	if _, err := store.Create("dev", internalConfig(), true); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.Root, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(store.Root, 0o700)
	if err := store.Remove("dev"); err == nil {
		t.Fatal("an unreadable store root should fail")
	}
}

func TestCloneConfigStrictMountJSON(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	if err := os.WriteFile(filepath.Join(host, "bad.json"), []byte(`{bad`), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, internalMountDefinition(host), resolver, true); err == nil {
		t.Fatal("strict mount clone should fail on invalid JSON")
	}
}

func TestCloneConfigSeedFileBudget(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	def := agent.Definition{Name: "seed", Strategy: agent.StrategySeed, ConfigDir: host}
	for i := 0; i <= maxCloneFiles; i++ {
		name := fmt.Sprintf("f%05d", i)
		if err := os.WriteFile(filepath.Join(host, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		def.SeedFiles = append(def.SeedFiles, agent.SeedSpec{Rel: name, Transform: agent.Identity{}})
	}
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, def, resolver, false); err == nil {
		t.Fatal("a clone over the file budget should fail")
	}
}

func TestCopyPathReadFileError(t *testing.T) {
	src := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(src, 0o600)
	var warnings []string
	var manifest []ManifestEntry
	if err := copyPath(src, filepath.Join(t.TempDir(), "out"), "secret", "test", nil, false, &cloneBudget{}, &warnings, &manifest); err == nil {
		t.Fatal("an unreadable file should fail")
	}
}

func TestLoadAndRemoveRefuseSymlinkedStoreRoot(t *testing.T) {
	real := internalStore(t)
	inst, err := real.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real.Root, link); err != nil {
		t.Fatal(err)
	}
	linked := &Store{Root: link}
	if _, err := linked.Load("dev"); err == nil {
		t.Fatal("Load through a symlinked store root must fail")
	}
	if err := linked.Remove("dev"); err == nil {
		t.Fatal("Remove through a symlinked store root must fail")
	}
	if _, err := os.Stat(inst.Dir); err != nil {
		t.Fatalf("instance should survive refused removal: %v", err)
	}
}

func TestLoadAndRemoveRejectUncleanRoot(t *testing.T) {
	real := internalStore(t)
	if _, err := real.Create("dev", internalConfig(), true); err != nil {
		t.Fatal(err)
	}
	unclean := &Store{Root: real.Root + "/."}
	if _, err := unclean.Load("dev"); err == nil {
		t.Fatal("an unclean root should fail the path check")
	}
	if err := unclean.Remove("dev"); err == nil {
		t.Fatal("an unclean root should fail the path check")
	}
}

func TestCloneConfigMountFileBudget(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	for i := 0; i <= maxCloneFiles; i++ {
		if err := os.WriteFile(filepath.Join(host, fmt.Sprintf("f%05d", i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, internalMountDefinition(host), resolver, false); err == nil {
		t.Fatal("a mount over the file budget should fail")
	}
}

func setFileSizeLimit(t *testing.T, limit uint64) func() {
	t.Helper()
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	next := old
	next.Cur = limit
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &next); err != nil {
		t.Fatal(err)
	}
	return func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old) }
}

func TestCreateWriteFailure(t *testing.T) {
	store := internalStore(t)
	restore := setFileSizeLimit(t, 0)
	_, err := store.Create("dev", internalConfig(), false)
	restore()
	if err == nil {
		t.Fatal("a failed config write should fail create")
	}
}

func TestCloneConfigSeedWriteFailure(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	if err := os.WriteFile(filepath.Join(host, "settings.json"), []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	def := agent.Definition{
		Name: "seed", Strategy: agent.StrategySeed, ConfigDir: host,
		SeedFiles: []agent.SeedSpec{{Rel: "settings.json", Transform: agent.Identity{}}},
	}
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	restore := setFileSizeLimit(t, 0)
	_, err = store.CloneConfig(inst, def, resolver, false)
	restore()
	if err == nil {
		t.Fatal("a failed seed write should fail the clone")
	}
}

func TestWriteFileAtomicWriteFailure(t *testing.T) {
	restore := setFileSizeLimit(t, 0)
	err := writeFileAtomic(filepath.Join(t.TempDir(), "x"), []byte("x"), 0o600)
	restore()
	if err == nil {
		t.Fatal("a write over the file-size limit should fail")
	}
}

func TestOpenStoreAbsFailure(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	t.Setenv(DirEnv, "relative")
	if _, err := OpenStore(); err == nil {
		t.Fatal("a relative root with an unusable cwd should fail")
	}
}

func TestCloneConfigRemoveTmpFailure(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(inst.Dir, configDirName+".new"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inst.Dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(inst.Dir, 0o700)
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, internalMountDefinition(t.TempDir()), resolver, false); err == nil {
		t.Fatal("an unremovable config.new should fail")
	}
}

func TestCreateMetadataWriteFailure(t *testing.T) {
	store := internalStore(t)
	restore := setFileSizeLimit(t, 10)
	_, err := store.Create("dev", config.File{}, false)
	restore()
	if err == nil {
		t.Fatal("a failed metadata write should fail create")
	}
}

func TestCreateEmptyStoreRoot(t *testing.T) {
	if _, err := (&Store{}).Create("dev", internalConfig(), false); err == nil {
		t.Fatal("an empty store root should fail")
	}
}

func TestCloneConfigRejectsEscapingSeed(t *testing.T) {
	store := internalStore(t)
	inst, err := store.Create("dev", internalConfig(), true)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	host := filepath.Join(parent, "host")
	if err := os.Mkdir(host, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "escape"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	def := agent.Definition{
		Name: "seed", Strategy: agent.StrategySeed, ConfigDir: host,
		SeedFiles: []agent.SeedSpec{{Rel: "../escape", Transform: agent.Identity{}}},
	}
	resolver := policy.NewResolver(fsx.Real{}, func(string) (string, bool) { return "", false })
	if _, err := store.CloneConfig(inst, def, resolver, false); err == nil {
		t.Fatal("a seed path escaping the config root should fail")
	}
}
