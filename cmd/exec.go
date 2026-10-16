package cmd

import (
	"fmt"
	"os"
	"os/exec"
)

// runExec runs a command in an already-live sandbox.
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

	argv := append([]string{"exec", "-i", "-t", name}, rest...)
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
