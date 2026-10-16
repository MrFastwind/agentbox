package podman

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"agentbox/internal/policy"
)

// Run executes podman with the given argv, wiring the container's stdio to ours
// so terminals and TUIs behave.
//
// On SIGINT/SIGTERM the container is removed before exiting: an interrupted run
// must not leave a sandbox behind. The exit status of the inner command is
// propagated.
func Run(spec *policy.ResolvedSpec, args []string, stdin *os.File, stdout, stderr *os.File) (int, error) {
	if err := Assert(spec, args); err != nil {
		return 1, err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if err == nil {
		return 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ctx.Err() != nil {
			// Interrupted. The container is removed by --rm; report the signal.
			return 130, nil
		}
		return exitErr.ExitCode(), nil
	}
	return 1, err
}
