package cmd

import (
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/agent"
	"agentbox/internal/cli"
	"agentbox/internal/policy"
	"agentbox/internal/session"
)

// --- helpers ----------------------------------------------------------------

func stubExec(t *testing.T, fn func(name string, arg ...string) *exec.Cmd) {
	t.Helper()
	saved := execCommand
	execCommand = fn
	t.Cleanup(func() { execCommand = saved })
}

func stubRun(t *testing.T, fn func(session.Options, agent.Definition, policy.Request) (int, error)) {
	t.Helper()
	saved := runSession
	runSession = fn
	t.Cleanup(func() { runSession = saved })
}

// capture redirects the process's stdout/stderr for the duration of fn.
func capture(t *testing.T, fn func() int) (int, string, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wOut, wErr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()

	code := fn()
	_ = wOut.Close()
	_ = wErr.Close()
	out, _ := io.ReadAll(rOut)
	errb, _ := io.ReadAll(rErr)
	return code, string(out), string(errb)
}

// --- flags ------------------------------------------------------------------

func TestStringSlice(t *testing.T) {
	var s stringSlice
	if s.String() != "" {
		t.Fatalf("empty String() = %q", s.String())
	}
	if err := s.Set("a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("b"); err != nil {
		t.Fatal(err)
	}
	if s.String() != "a,b" {
		t.Fatalf("String() = %q, want a,b", s.String())
	}
}

func TestSortedMountSummary(t *testing.T) {
	ms := []policy.ResolvedMount{
		{Host: "/b", Dest: "/z", Access: policy.RO},
		{Host: "/a", Dest: "/y", Access: policy.RW},
	}
	got := sortedMountSummary(ms)
	if len(got) != 2 || got[0] != "/a:/y:rw" || got[1] != "/b:/z:ro" {
		t.Fatalf("sortedMountSummary = %v", got)
	}
}

func TestIsTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminal(r) {
		t.Fatal("a pipe must not be reported as a terminal")
	}
	if devnull, err := os.Open(os.DevNull); err == nil {
		defer devnull.Close()
		if !isTerminal(devnull) {
			t.Fatal("/dev/null is a character device and should be reported as a terminal")
		}
	}
}

func TestUsagePrintsHelp(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var sb strings.Builder
	fs.SetOutput(&sb)
	usage(fs)
	if !strings.Contains(sb.String(), "Usage:") {
		t.Fatalf("usage output missing usage block:\n%s", sb.String())
	}
}

// --- Main dispatch ----------------------------------------------------------

func TestMainVersion(t *testing.T) {
	code, out, _ := capture(t, func() int { return Main([]string{"version"}) })
	if code != 0 {
		t.Fatalf("version exit = %d, want 0", code)
	}
	if !strings.Contains(out, version) {
		t.Fatalf("version output = %q, want it to contain %q", out, version)
	}
}

// A first argument that is not a reserved word is a command to run in the
// sandbox, not an unknown subcommand.
func TestMainTreatsNonReservedAsCommand(t *testing.T) {
	var gotReq policy.Request
	stubRun(t, func(_ session.Options, _ agent.Definition, req policy.Request) (int, error) {
		gotReq = req
		return 0, nil
	})
	code, _, errb := capture(t, func() int { return Main([]string{"bogus", "arg"}) })
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, errb)
	}
	if strings.Join(gotReq.Command, " ") != "bogus arg" {
		t.Fatalf("pass-through command = %v", gotReq.Command)
	}
}

func TestMainDispatchesSubcommands(t *testing.T) {
	stubExec(t, func(name string, arg ...string) *exec.Cmd { return exec.Command("sh", "-c", "echo ok") })
	cases := []struct {
		argv []string
		want int
	}{
		{[]string{"doctor"}, 0},
		{[]string{"images"}, 2}, // missing "build"
		{[]string{"exec"}, 2},   // missing name
	}
	for _, tc := range cases {
		code, _, _ := capture(t, func() int { return Main(tc.argv) })
		if code != tc.want {
			t.Errorf("Main(%v) = %d, want %d", tc.argv, code, tc.want)
		}
	}
}

// --- runRoot ----------------------------------------------------------------

func TestRunRootPrintArgv(t *testing.T) {
	code, out, errb := capture(t, func() int {
		return runRoot(cli.Invocation{Args: []string{"--print-argv", "--agent", "shell"}})
	})
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, errb)
	}
	for _, want := range []string{"--read-only", "--http-proxy=false", "localhost/agentbox/base:latest"} {
		if !strings.Contains(out, want) {
			t.Fatalf("printed argv missing %q:\n%s", want, out)
		}
	}
}

func TestRunRootUnknownAgent(t *testing.T) {
	code, _, errb := capture(t, func() int {
		return runRoot(cli.Invocation{Args: []string{"--agent", "nope"}})
	})
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "unknown agent") {
		t.Fatalf("stderr = %q", errb)
	}
}

func TestRunRootBadFlag(t *testing.T) {
	code, _, _ := capture(t, func() int {
		return runRoot(cli.Invocation{Args: []string{"--definitely-not-a-flag"}})
	})
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestRunRootMissingConfigFile(t *testing.T) {
	code, _, errb := capture(t, func() int {
		return runRoot(cli.Invocation{Args: []string{"--config", filepath.Join(t.TempDir(), "nope.yaml")}})
	})
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "opening config") {
		t.Fatalf("stderr = %q", errb)
	}
}

func TestRunRootRefusesBadImage(t *testing.T) {
	code, _, errb := capture(t, func() int {
		return runRoot(cli.Invocation{Args: []string{"--agent", "shell", "--image", "debian", "--print-argv"}})
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "image") {
		t.Fatalf("stderr = %q", errb)
	}
}

func TestRunRootAuditLogOpenFailure(t *testing.T) {
	code, _, errb := capture(t, func() int {
		return runRoot(cli.Invocation{Args: []string{
			"--agent", "shell", "--print-argv",
			"--audit-log", filepath.Join(t.TempDir(), "missing-dir", "audit.jsonl"),
		}})
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "audit log") {
		t.Fatalf("stderr = %q", errb)
	}
}

func TestRunRootWritesAuditLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	code, _, errb := capture(t, func() int {
		return runRoot(cli.Invocation{Args: []string{"--agent", "shell", "--print-argv", "--audit-log", path}})
	})
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, errb)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Fatalf("audit log not written: %v", err)
	}
}

// A project configuration file supplies defaults that flags may override.
func TestRunRootConfigMerging(t *testing.T) {
	var gotReq policy.Request
	stubRun(t, func(_ session.Options, _ agent.Definition, req policy.Request) (int, error) {
		gotReq = req
		return 0, nil
	})

	cfg := filepath.Join(t.TempDir(), "agentbox.yaml")
	body := "agent: shell\n" +
		"network: none\n" +
		"memory: 2g\n" +
		"cpus: \"1\"\n" +
		"pids_limit: 100\n" +
		"env:\n  - TERM\n" +
		"mounts:\n  - /tmp/src:/data:ro\n" +
		"command:\n  - echo\n  - from-cfg\n" +
		"user_config: false\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, errb := capture(t, func() int {
		return runRoot(cli.Invocation{Args: []string{"--config", cfg}})
	})
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, errb)
	}
	if gotReq.NetworkMode != "none" || gotReq.Memory != "2g" || gotReq.CPUs != "1" || gotReq.PidsLimit != 100 {
		t.Fatalf("resource/network config not merged: %+v", gotReq)
	}
	if strings.Join(gotReq.EnvNames, ",") != "TERM" {
		t.Fatalf("env not merged: %v", gotReq.EnvNames)
	}
	if len(gotReq.ExtraMounts) != 1 || gotReq.ExtraMounts[0] != "/tmp/src:/data:ro" {
		t.Fatalf("mounts not merged: %v", gotReq.ExtraMounts)
	}
	if strings.Join(gotReq.Command, " ") != "echo from-cfg" {
		t.Fatalf("command from config not used: %v", gotReq.Command)
	}
	if !gotReq.NoUserConfig {
		t.Fatal("user_config:false must force --no-user-config behaviour")
	}
}

// An explicit "--" invocation passes the whole remainder through unparsed.
func TestRunRootExplicitCommand(t *testing.T) {
	var gotReq policy.Request
	stubRun(t, func(_ session.Options, _ agent.Definition, req policy.Request) (int, error) {
		gotReq = req
		return 0, nil
	})
	code, _, _ := capture(t, func() int {
		return runRoot(cli.Invocation{Explicit: true, Args: []string{"npm", "test"}})
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.Join(gotReq.Command, " ") != "npm test" {
		t.Fatalf("pass-through command not forwarded: %v", gotReq.Command)
	}
}

func TestRunRootForceShellOverridesCommand(t *testing.T) {
	var gotDef agent.Definition
	stubRun(t, func(_ session.Options, def agent.Definition, _ policy.Request) (int, error) {
		gotDef = def
		return 0, nil
	})
	code, _, errb := capture(t, func() int {
		return runRoot(cli.Invocation{Args: []string{"--agent", "opencode", "--no-user-config", "--shell"}})
	})
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, errb)
	}
	if strings.Join(gotDef.Command, " ") != "/bin/bash -l" {
		t.Fatalf("--shell did not override the command: %v", gotDef.Command)
	}
}

// --- runExec ----------------------------------------------------------------

func TestRunExecUsage(t *testing.T) {
	code, _, errb := capture(t, func() int { return runExec(nil) })
	if code != 2 || !strings.Contains(errb, "usage") {
		t.Fatalf("runExec(nil) = %d, stderr=%q", code, errb)
	}
}

func TestRunExecSuccess(t *testing.T) {
	var argv []string
	stubExec(t, func(name string, arg ...string) *exec.Cmd {
		argv = append([]string{name}, arg...)
		return exec.Command("sh", "-c", "exit 0")
	})
	code, _, _ := capture(t, func() int { return runExec([]string{"mybox", "--", "echo", "hi"}) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.Join(argv, " ") != "podman exec -i -t mybox echo hi" {
		t.Fatalf("exec argv = %v", argv)
	}
}

func TestRunExecDefaultsToShell(t *testing.T) {
	var argv []string
	stubExec(t, func(name string, arg ...string) *exec.Cmd {
		argv = append([]string{name}, arg...)
		return exec.Command("sh", "-c", "exit 0")
	})
	code, _, _ := capture(t, func() int { return runExec([]string{"mybox"}) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.Join(argv, " ") != "podman exec -i -t mybox /bin/bash -l" {
		t.Fatalf("exec argv = %v", argv)
	}
}

func TestRunExecPropagatesExitCode(t *testing.T) {
	stubExec(t, func(name string, arg ...string) *exec.Cmd { return exec.Command("sh", "-c", "exit 3") })
	code, _, _ := capture(t, func() int { return runExec([]string{"mybox"}) })
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestRunExecStartFailure(t *testing.T) {
	stubExec(t, func(name string, arg ...string) *exec.Cmd { return exec.Command("/nonexistent/agentbox-xyz") })
	code, _, errb := capture(t, func() int { return runExec([]string{"mybox"}) })
	if code != 1 || !strings.Contains(errb, "exec") {
		t.Fatalf("runExec = %d, stderr=%q", code, errb)
	}
}

// --- runImages --------------------------------------------------------------

func writeContainerfiles(t *testing.T, targets ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, target := range targets {
		if err := os.WriteFile(filepath.Join(dir, "Containerfile."+target), []byte("FROM scratch\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AGENTBOX_IMAGE_DIR", dir)
	return dir
}

func TestRunImagesUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"push"}} {
		code, _, errb := capture(t, func() int { return runImages(args) })
		if code != 2 || !strings.Contains(errb, "usage") {
			t.Fatalf("runImages(%v) = %d, stderr=%q", args, code, errb)
		}
	}
}

func TestRunImagesBuilds(t *testing.T) {
	writeContainerFilesHelper(t)
	var builds []string
	stubExec(t, func(name string, arg ...string) *exec.Cmd {
		builds = append(builds, strings.Join(arg, " "))
		return exec.Command("sh", "-c", "exit 0")
	})
	code, _, errb := capture(t, func() int { return runImages([]string{"build"}) })
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, errb)
	}
	if len(builds) != 3 {
		t.Fatalf("expected 3 builds (base, opencode, pi), got %d: %v", len(builds), builds)
	}
	// Non-base targets must receive the fully-qualified BASE build-arg.
	for _, b := range builds[1:] {
		if !strings.Contains(b, "--build-arg BASE=localhost/agentbox/base:latest") {
			t.Fatalf("missing BASE build-arg: %s", b)
		}
	}
}

func TestRunImagesMissingContainerfile(t *testing.T) {
	writeContainerFilesHelper(t)
	stubExec(t, func(name string, arg ...string) *exec.Cmd { return exec.Command("sh", "-c", "exit 0") })
	code, _, errb := capture(t, func() int { return runImages([]string{"build", "nope"}) })
	if code != 1 || !strings.Contains(errb, "no Containerfile") {
		t.Fatalf("runImages = %d, stderr=%q", code, errb)
	}
}

func TestRunImagesBuildFailure(t *testing.T) {
	writeContainerFilesHelper(t)
	stubExec(t, func(name string, arg ...string) *exec.Cmd { return exec.Command("sh", "-c", "exit 1") })
	code, _, errb := capture(t, func() int { return runImages([]string{"build", "base"}) })
	if code != 1 || !strings.Contains(errb, "build failed") {
		t.Fatalf("runImages = %d, stderr=%q", code, errb)
	}
}

func writeContainerFilesHelper(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, tgt := range []string{"base", "opencode", "pi", "shell"} {
		if err := os.WriteFile(filepath.Join(dir, "Containerfile."+tgt), []byte("FROM scratch\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AGENTBOX_IMAGE_DIR", dir)
}

func TestImageDirOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENTBOX_IMAGE_DIR", dir)
	got, err := imageDir()
	if err != nil || got != dir {
		t.Fatalf("imageDir() = %q, %v; want %q", got, err, dir)
	}
}

func TestImageDirFallsBackToSourceTree(t *testing.T) {
	t.Setenv("AGENTBOX_IMAGE_DIR", "")
	got, err := imageDir()
	if err != nil {
		t.Fatalf("imageDir() from a source checkout should resolve: %v", err)
	}
	if _, err := os.Stat(filepath.Join(got, "Containerfile.base")); err != nil {
		t.Fatalf("imageDir() returned %q without Containerfile.base", got)
	}
}

// --- doctor -----------------------------------------------------------------

func TestPodmanLineReportsAvailability(t *testing.T) {
	stubExec(t, func(name string, arg ...string) *exec.Cmd { return exec.Command("sh", "-c", "echo 4.9.3") })
	if got := podmanLine("version"); got != "ok" && got != "4.9.3" {
		t.Fatalf("podmanLine success = %q", got)
	}
}

func TestPodmanLineUnavailable(t *testing.T) {
	stubExec(t, func(name string, arg ...string) *exec.Cmd { return exec.Command("/nonexistent/podman-xyz") })
	if got := podmanLine("version"); !strings.HasPrefix(got, "unavailable") {
		t.Fatalf("podmanLine failure = %q", got)
	}
}

func TestRunDoctorReports(t *testing.T) {
	stubExec(t, func(name string, arg ...string) *exec.Cmd { return exec.Command("sh", "-c", "echo x") })
	code, out, _ := capture(t, func() int { return runDoctor(nil) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	for _, want := range []string{"agentbox doctor", "runtime", "agents", "modes", "network", "workspace"} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
}
