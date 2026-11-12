package podman

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"agentbox/internal/policy"
)

func validSpec() *policy.ResolvedSpec {
	return &policy.ResolvedSpec{
		Agent:    "opencode",
		Image:    "localhost/agentbox/opencode:latest",
		Command:  []string{"opencode"},
		Hostname: "agentbox-opencode",
		Userns:   "keep-id",
		CapDrop:  true,
		ReadOnly: true,
		UnsetEnv: true,
		Limits:   policy.Limits{Pids: 2048},
		Mounts: []policy.ResolvedMount{
			{Host: "/home/u/project", Dest: "/workspace", Access: policy.RW, Origin: "launch-dir"},
		},
	}
}

func validArgs() []string {
	return []string{
		"run", "--rm",
		"--hostname", "agentbox-opencode",
		"--http-proxy=false", "--unsetenv-all",
		"--cap-drop", "ALL", "--read-only", "--ulimit", "core=0",
		"--security-opt", "seccomp=/run/agentbox/seccomp.json",
		"--volume", "/home/u/project:/workspace:rw",
		"localhost/agentbox/opencode:latest",
	}
}

func swapCommandContext(t *testing.T, fn func(ctx context.Context, name string, arg ...string) *exec.Cmd) {
	t.Helper()
	old := commandContext
	commandContext = fn
	t.Cleanup(func() { commandContext = old })
}

func TestRunPropagatesExitCode(t *testing.T) {
	swapCommandContext(t, func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "exit 7")
	})
	code, err := run(context.Background(), []string{"x"}, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 7 {
		t.Fatalf("exit code not propagated: got %d, want 7", code)
	}
}

func TestRunSuccessReturnsZero(t *testing.T) {
	swapCommandContext(t, func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "exit 0")
	})
	code, err := run(context.Background(), []string{"x"}, nil, nil, nil)
	if err != nil || code != 0 {
		t.Fatalf("got (%d, %v), want (0, nil)", code, err)
	}
}

// An interruption must map to 130 and not surface as an error: the run was
// deliberately torn down, and --rm removes the container.
func TestRunInterruptReturns130(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	swapCommandContext(t, func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "sleep 5")
	})
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	code, err := run(ctx, []string{"x"}, nil, nil, nil)
	if err != nil {
		t.Fatalf("interrupt must not surface as an error: %v", err)
	}
	if code != 130 {
		t.Fatalf("interrupt must map to 130, got %d", code)
	}
}

// A failure that is not an ExitError (e.g. the binary is missing) is reported as
// an error, not as a fake exit code.
func TestRunExecFailureReturnsError(t *testing.T) {
	swapCommandContext(t, func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/nonexistent/agentbox-podman-xyz")
	})
	code, err := run(context.Background(), []string{"x"}, nil, nil, nil)
	if err == nil {
		t.Fatal("expected an error when the process cannot start")
	}
	if code != 1 {
		t.Fatalf("expected code 1 on exec failure, got %d", code)
	}
}

// Run must consult Assert before touching podman: a spec that violates the
// invariants returns immediately and never starts a process.
func TestRunAssertsBeforeExec(t *testing.T) {
	called := false
	swapCommandContext(t, func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		called = true
		return exec.CommandContext(ctx, "sh", "-c", "exit 0")
	})
	// Args missing the required hardening tokens.
	_, err := Run(validSpec(), []string{"run", "--rm", "img"}, nil, nil, nil)
	if err == nil {
		t.Fatal("Run must reject an argv that violates the invariants")
	}
	if called {
		t.Fatal("Run must not start podman when Assert fails")
	}
}

func TestRunRunsValidArgv(t *testing.T) {
	code := -1
	swapCommandContext(t, func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		if name != "podman" {
			t.Fatalf("expected the podman binary, got %q", name)
		}
		return exec.CommandContext(ctx, "sh", "-c", "exit 0")
	})
	var err error
	code, err = Run(validSpec(), validArgs(), nil, nil, nil)
	if err != nil || code != 0 {
		t.Fatalf("Run(valid) = (%d, %v), want (0, nil)", code, err)
	}
}
