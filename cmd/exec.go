package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"agentbox/internal/instance"
)

// runExec runs a command in an already-live sandbox. The argument is resolved as
// an exact container name first, so existing scripts keep working, then as an
// instance name, which maps to agentbox-<name>.
func runExec(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentbox exec <name> -- <command...>")
		return 2
	}
	name := args[0]
	rest := args[1:]
	// A leading "--" is the documented separator.
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		rest = []string{"/bin/bash", "-l"}
	}

	container := name
	if _, ok := podmanContainerStatus(name); !ok {
		store, err := instance.OpenStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: exec: %v\n", err)
			return 1
		}
		inst, err := store.Load(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: exec: no container or instance %q\n", name)
			return 1
		}
		container = inst.ContainerName()
	}

	argv := append([]string{"exec", "-i", "-t", container}, rest...)
	cmd := execCommand("podman", argv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "agentbox: exec: %v\n", err)
		return 1
	}
	return 0
}
