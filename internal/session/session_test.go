package session

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/agent"
	"agentbox/internal/audit"
	"agentbox/internal/fsx"
	"agentbox/internal/policy"
)

const (
	testHome    = "/home/u"
	testProject = testHome + "/project"
)

// baseDef is a minimal agent definition that exercises every boot stage: a
// launch dir, a named state directory set, and one allow-listed seed file.
func baseDef() agent.Definition {
	return agent.Definition{
		Name:                 "ci",
		Image:                "localhost/agentbox/base:latest",
		Command:              []string{"/bin/bash", "-l"},
		Strategy:             agent.StrategySeed,
		ConfigDir:            "/cfg",
		ConfigDirInContainer: "/home/agent/.config/ci",
		SeedFiles:            []agent.SeedSpec{{Rel: "settings.json", Transform: agent.Identity{}}},
		BaseEnv:              map[string]string{"HOME": "/home/agent", "PATH": "/usr/bin"},
		StateDirs:            []string{"/home/agent", "/home/agent/.config"},
	}
}

func fakeHost() *fsx.Fake {
	f := fsx.NewFake(testHome, testProject)
	f.Mkdir(testProject)
	f.Mkdir("/cfg")
	f.Write("/cfg/settings.json", []byte(`{"theme":"dark"}`))
	return f
}

func noEnv(string) (string, bool) { return "", false }

func options(f *fsx.Fake, out *os.File) Options {
	return Options{
		Resolver: policy.NewResolver(f, noEnv),
		Stdout:   out,
	}
}

type runFn func(*policy.ResolvedSpec, []string, *os.File, *os.File, *os.File) (int, error)

func withRun(t *testing.T, fn runFn) {
	t.Helper()
	saved := runPodman
	runPodman = fn
	t.Cleanup(func() { runPodman = saved })
}

func hasMount(spec *policy.ResolvedSpec, origin, dest string) bool {
	for _, m := range spec.Mounts {
		if m.Origin == origin && m.Dest == dest {
			return true
		}
	}
	return false
}

func argValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func hasSeccompArg(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "seccomp=") && len(a) > len("seccomp=") {
			return true
		}
	}
	return false
}

func TestBootPrintArgvStagesAndDoesNotRun(t *testing.T) {
	withRun(t, func(*policy.ResolvedSpec, []string, *os.File, *os.File, *os.File) (int, error) {
		t.Fatal("PrintArgv must not invoke podman")
		return 1, nil
	})

	out, err := os.CreateTemp(t.TempDir(), "argv")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	o := options(fakeHost(), out)
	o.PrintArgv = true
	code, err := o.Boot(baseDef(), policy.Request{LaunchDir: testProject})
	if err != nil || code != 0 {
		t.Fatalf("Boot = (%d, %v), want (0, nil)", code, err)
	}

	raw, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	printed := string(raw)
	for _, want := range []string{"--read-only", "--http-proxy=false", "--unsetenv-all", "--cap-drop"} {
		if !strings.Contains(printed, want) {
			t.Fatalf("printed argv missing %q:\n%s", want, printed)
		}
	}
}

func TestBootPrintArgvShowsInstalledVersion(t *testing.T) {
	withRun(t, func(*policy.ResolvedSpec, []string, *os.File, *os.File, *os.File) (int, error) {
		t.Fatal("PrintArgv must not invoke podman")
		return 1, nil
	})
	out, err := os.CreateTemp(t.TempDir(), "argv")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	o := options(fakeHost(), out)
	o.PrintArgv = true
	if code, err := o.Boot(baseDef(), policy.Request{LaunchDir: testProject, ImageVersion: "2.4.1"}); err != nil || code != 0 {
		t.Fatalf("Boot = (%d, %v)", code, err)
	}
	raw, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "# image localhost/agentbox/base:latest version 2.4.1\n") {
		t.Fatalf("printed argv missing version comment:\n%s", raw)
	}
}

func TestBootStagesStateAndSeedsAndRuns(t *testing.T) {
	var gotSpec *policy.ResolvedSpec
	var gotArgs []string
	var seedFile []byte
	var seedMode os.FileMode
	var stateHost string

	withRun(t, func(spec *policy.ResolvedSpec, args []string, _ *os.File, _ *os.File, _ *os.File) (int, error) {
		gotSpec, gotArgs = spec, args
		for _, m := range spec.Mounts {
			switch m.Origin {
			case "state":
				stateHost = m.Host
			case "seed":
				info, err := os.Stat(filepath.Join(m.Host, "settings.json"))
				if err != nil {
					return 1, err
				}
				seedMode = info.Mode().Perm()
				seedFile, _ = os.ReadFile(filepath.Join(m.Host, "settings.json"))
			}
		}
		return 0, nil
	})

	code, err := options(fakeHost(), nil).Boot(baseDef(), policy.Request{LaunchDir: testProject})
	if err != nil || code != 0 {
		t.Fatalf("Boot = (%d, %v), want (0, nil)", code, err)
	}

	if stateHost == "" || !hasMount(gotSpec, "state", agent.ContainerHome) {
		t.Fatalf("ephemeral HOME not mounted at %s: %+v", agent.ContainerHome, gotSpec.Mounts)
	}
	if !hasMount(gotSpec, "seed", "/run/agentbox/seeds") {
		t.Fatalf("seed staging not mounted: %+v", gotSpec.Mounts)
	}
	if string(seedFile) != `{"theme":"dark"}` {
		t.Fatalf("seed staged with wrong bytes: %q", seedFile)
	}
	if seedMode != 0o600 {
		t.Fatalf("seed staged with mode %v, want 0600", seedMode)
	}
	if !contains(gotArgs, "--read-only") {
		t.Fatalf("rendered argv lost hardening: %v", gotArgs)
	}
	if !hasSeccompArg(gotArgs) {
		t.Fatalf("rendered argv does not install a seccomp profile: %v", gotArgs)
	}

	// The ephemeral HOME is removed when Boot returns.
	if _, err := os.Stat(stateHost); !os.IsNotExist(err) {
		t.Fatalf("ephemeral HOME %s was not cleaned up (err=%v)", stateHost, err)
	}
}

func TestBootGeneratesNameWhenEmpty(t *testing.T) {
	var name string
	withRun(t, func(_ *policy.ResolvedSpec, args []string, _ *os.File, _ *os.File, _ *os.File) (int, error) {
		name, _ = argValue(args, "--name")
		return 0, nil
	})
	if _, err := options(fakeHost(), nil).Boot(baseDef(), policy.Request{LaunchDir: testProject}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "agentbox-") {
		t.Fatalf("generated name not derived from the program name: %q", name)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(name, "agentbox-")); err != nil {
		t.Fatalf("generated name is not hex-encoded: %q", name)
	}
}

func TestBootUsesProvidedName(t *testing.T) {
	var name string
	withRun(t, func(_ *policy.ResolvedSpec, args []string, _ *os.File, _ *os.File, _ *os.File) (int, error) {
		name, _ = argValue(args, "--name")
		return 0, nil
	})
	o := options(fakeHost(), nil)
	o.Name = "my-container"
	if _, err := o.Boot(baseDef(), policy.Request{LaunchDir: testProject}); err != nil {
		t.Fatal(err)
	}
	if name != "my-container" {
		t.Fatalf("explicit container name not honoured: %q", name)
	}
}

// The container hostname follows the agent name, so the box is identifiable
// from inside without the user passing anything.
func TestBootSetsHostnameFromAgent(t *testing.T) {
	var hostname string
	withRun(t, func(_ *policy.ResolvedSpec, args []string, _ *os.File, _ *os.File, _ *os.File) (int, error) {
		hostname, _ = argValue(args, "--hostname")
		return 0, nil
	})
	if _, err := options(fakeHost(), nil).Boot(baseDef(), policy.Request{LaunchDir: testProject}); err != nil {
		t.Fatal(err)
	}
	if hostname != "agentbox-ci" {
		t.Fatalf("hostname = %q, want agentbox-ci", hostname)
	}
}

// The audit record is written before podman starts and must never carry a
// credential value, only the name that identifies it.
func TestBootRecordsAuditWithoutSecrets(t *testing.T) {
	withRun(t, func(*policy.ResolvedSpec, []string, *os.File, *os.File, *os.File) (int, error) {
		return 0, nil
	})

	def := baseDef()
	def.BaseEnv["TOKEN"] = "s3cr3t-value"

	var log strings.Builder
	o := options(fakeHost(), nil)
	o.Audit = audit.New(&log)

	if _, err := o.Boot(def, policy.Request{LaunchDir: testProject}); err != nil {
		t.Fatal(err)
	}
	if log.Len() == 0 {
		t.Fatal("audit logger recorded nothing")
	}
	if strings.Contains(log.String(), "s3cr3t-value") {
		t.Fatalf("credential leaked into the audit record:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "TOKEN") {
		t.Fatalf("env name missing from the audit record:\n%s", log.String())
	}
}

// A resolver failure must stop Boot before any ephemeral directory is created.
func TestBootResolverFailureReturnsError(t *testing.T) {
	withRun(t, func(*policy.ResolvedSpec, []string, *os.File, *os.File, *os.File) (int, error) {
		t.Fatal("podman must not run when resolution fails")
		return 1, nil
	})
	// A launch directory that does not exist cannot be resolved.
	code, err := options(fakeHost(), nil).Boot(baseDef(), policy.Request{LaunchDir: "/does/not/exist"})
	if err == nil {
		t.Fatal("expected a refusal for a missing launch directory")
	}
	if code != 1 {
		t.Fatalf("refusal should report code 1, got %d", code)
	}
}

// A decision not to mount something has to be visible where the user is
// looking. The audit log is opt-in, so a warning that only reaches it might as
// well not exist: a skipped config symlink would still be discovered by the
// agent failing to find its skills.
func TestBootPrintsNonFatalWarningsToStderr(t *testing.T) {
	withRun(t, func(*policy.ResolvedSpec, []string, *os.File, *os.File, *os.File) (int, error) {
		return 0, nil
	})

	out, err := os.CreateTemp(t.TempDir(), "argv")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderrR.Close()

	f := fsx.NewFake(testHome, testProject)
	f.Mkdir(testProject)
	f.Write("/etc/passwd", []byte("root:x:0:0"))
	f.Mkdir(testHome + "/.config/opencode")
	f.Write(testHome+"/.config/opencode/opencode.json", []byte(`{"model":"m"}`))
	f.Symlink("/etc/passwd", testHome+"/.config/opencode/escape")

	def := agent.Definition{
		Name:                  "ci",
		Image:                 "localhost/agentbox/base:latest",
		Command:               []string{"/bin/bash", "-l"},
		Strategy:              agent.StrategyMount,
		ConfigDir:             testHome + "/.config/opencode",
		ConfigDirInContainer:  "/home/agent/.config/opencode",
		SymlinkTargetPrefixes: []string{testHome},
		BaseEnv:               map[string]string{"HOME": "/home/agent", "PATH": "/usr/bin"},
		StateDirs:             []string{"/home/agent"},
	}

	o := options(f, out)
	o.Stderr = stderrW
	if code, err := o.Boot(def, policy.Request{LaunchDir: testProject}); err != nil || code != 0 {
		t.Fatalf("Boot = (%d, %v), want (0, nil)", code, err)
	}
	if err := stderrW.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := io.ReadAll(stderrR)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "outside the allowed prefixes") {
		t.Fatalf("stderr must explain the skipped symlink, got: %q", raw)
	}
}

func TestPrepareStateDirsCreatesPrivateDirs(t *testing.T) {
	stateDir := t.TempDir()
	if err := prepareStateDirs(stateDir, []string{"/home/agent", "/home/agent/.config", "/home/agent/.local/share"}); err != nil {
		t.Fatalf("prepareStateDirs: %v", err)
	}
	for _, rel := range []string{"", ".config", ".local/share"} {
		p := filepath.Join(stateDir, rel)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("state dir %q not created: %v", p, err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("state dir %q mode = %v, want 0700", p, info.Mode().Perm())
		}
	}
}

func TestPrepareStateDirsErrorIsReported(t *testing.T) {
	// A file where a directory is expected must surface as an error, not a
	// silent skip: the agent's HOME would otherwise be unwritable.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirs(file, []string{"/home/agent"}); err == nil {
		t.Fatal("expected an error when the state path exists as a file")
	}
}

func TestWriteSeedsMirrorsRelativePaths(t *testing.T) {
	dir := t.TempDir()
	seeds := []policy.SeededFile{
		{Rel: "settings.json", Data: []byte("a")},
		{Rel: "nested/models.json", Data: []byte("b")},
	}
	if err := writeSeeds(dir, seeds); err != nil {
		t.Fatalf("writeSeeds: %v", err)
	}
	for _, s := range seeds {
		p := filepath.Join(dir, filepath.FromSlash(s.Rel))
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("seed %q not written: %v", s.Rel, err)
		}
		if string(got) != string(s.Data) {
			t.Fatalf("seed %q = %q, want %q", s.Rel, got, s.Data)
		}
		info, _ := os.Stat(p)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("seed %q mode = %v, want 0600", s.Rel, info.Mode().Perm())
		}
	}
}

func TestWriteSeedsErrorIsReported(t *testing.T) {
	dir := t.TempDir()
	// A file where a directory is expected must surface as an error.
	file := filepath.Join(dir, "blocker")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeSeeds(dir, []policy.SeededFile{{Rel: "blocker/child.json", Data: []byte("y")}}); err == nil {
		t.Fatal("expected an error when a seed's parent path is a file")
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"run", "--rm"}, "run --rm"},
		{[]string{"--env", "A=b c"}, "--env 'A=b c'"},
		{[]string{"it's"}, `'it'\''s'`},
		{[]string{""}, "''"},
		{[]string{"a$b", "x`y`", "p|q", "r&s", "semi;colon"}, "'a$b' 'x`y`' 'p|q' 'r&s' 'semi;colon'"},
	}
	for _, tc := range cases {
		if got := shellQuote(tc.in); got != tc.want {
			t.Fatalf("shellQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPrepareStateDirsNoFollowCreatesAndTightens(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirsNoFollow(home, []string{"/home/agent", "/home/agent/.config", "/home/agent/.local/share/ci"}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{home, filepath.Join(home, ".config"), filepath.Join(home, ".local"), filepath.Join(home, ".local", "share"), filepath.Join(home, ".local", "share", "ci")} {
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %04o, want directory 0700", dir, fi.Mode().Perm())
		}
	}
}

func TestPrepareStateDirsNoFollowRefusesSymlink(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".config")); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirsNoFollow(home, []string{"/home/agent/.config/ci"}); err == nil {
		t.Fatal("a symlinked state component must be refused")
	}
}

func TestPrepareStateDirsNoFollowRefusesFile(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirsNoFollow(home, []string{"/home/agent/.config/ci"}); err == nil {
		t.Fatal("a non-directory state component must be refused")
	}
}

func TestPrepareStateDirsNoFollowRefusesSymlinkedHome(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirsNoFollow(link, nil); err == nil {
		t.Fatal("a symlinked instance home must be refused")
	}
}

func TestBootUsesPersistentInstanceHome(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	instDir := filepath.Join(root, "dev")
	home := filepath.Join(instDir, "home")
	config := filepath.Join(instDir, "config")
	for _, dir := range []string{instDir, home, config} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(config, "settings.json"), []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	f := fsx.NewFake(testHome, testProject)
	f.Mkdir(testProject)
	f.Mkdir(root)
	f.Paths[root] = fsx.FakeEntry{Dir: true, Mode: 0o700}
	f.Mkdir(instDir)
	f.Paths[instDir] = fsx.FakeEntry{Dir: true, Mode: 0o700}
	f.Mkdir(home)
	f.Paths[home] = fsx.FakeEntry{Dir: true, Mode: 0o700}
	f.Mkdir(config)
	f.Write(filepath.Join(config, "settings.json"), []byte(`{"theme":"dark"}`))
	f.Paths[config] = fsx.FakeEntry{Dir: true, Mode: 0o700}

	withRun(t, func(*policy.ResolvedSpec, []string, *os.File, *os.File, *os.File) (int, error) {
		t.Fatal("PrintArgv must not invoke podman")
		return 1, nil
	})
	out, err := os.CreateTemp(t.TempDir(), "argv")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	o := options(f, out)
	o.PrintArgv = true
	req := policy.Request{
		LaunchDir:    testProject,
		InstanceName: "dev",
		InstanceRoot: root,
		InstanceHome: home,
		ConfigRoot:   config,
	}
	code, err := o.Boot(baseDef(), req)
	if err != nil || code != 0 {
		t.Fatalf("Boot = (%d, %v)", code, err)
	}
	raw, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	printed := string(raw)
	if !strings.Contains(printed, home+":/home/agent:rw") {
		t.Fatalf("persistent HOME not mounted:\n%s", printed)
	}
	if strings.Contains(printed, "agentbox-state-") {
		t.Fatalf("persistent instance should not use an ephemeral HOME:\n%s", printed)
	}
	if _, err := os.Stat(filepath.Join(home, ".config")); err != nil {
		t.Fatalf("state directories should be prepared in the persistent HOME: %v", err)
	}
}

func TestPrepareStateDirsNoFollowErrors(t *testing.T) {
	t.Run("missing home", func(t *testing.T) {
		if err := prepareStateDirsNoFollow(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
			t.Fatal("missing home should fail")
		}
	})
	t.Run("home is file", func(t *testing.T) {
		home := filepath.Join(t.TempDir(), "home")
		if err := os.WriteFile(home, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := prepareStateDirsNoFollow(home, nil); err == nil {
			t.Fatal("a file home should fail")
		}
	})
	t.Run("dotdot component", func(t *testing.T) {
		home := t.TempDir()
		if err := prepareStateDirsNoFollow(home, []string{"/home/agent/../escape"}); err == nil {
			t.Fatal(".. must be refused")
		}
	})
	t.Run("empty component", func(t *testing.T) {
		home := t.TempDir()
		if err := prepareStateDirsNoFollow(home, []string{"/home/agent//escape"}); err == nil {
			t.Fatal("empty components must be refused")
		}
	})
	t.Run("mkdir failure", func(t *testing.T) {
		home := t.TempDir()
		if err := os.Chmod(home, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(home, 0o700)
		if err := prepareStateDirsNoFollow(home, []string{"/home/agent/.config"}); err == nil {
			t.Fatal("an unwritable home should fail")
		}
	})
}
