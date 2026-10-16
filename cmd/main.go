package cmd

import (
	"fmt"
	"os"

	"container-agent/internal/cli"
)

// version is the build version.
var version = "0.1.0-dev"

// Main dispatches the command line and returns the process exit code.
func Main(argv []string) int {
	inv := cli.Split(argv)

	switch inv.Subcommand {
	case "":
		return runRoot(inv)
	case "doctor":
		return runDoctor(inv.Args)
	case "images":
		return runImages(inv.Args)
	case "exec":
		return runExec(inv.Args)
	case "version":
		fmt.Println(version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", inv.Subcommand)
		return 2
	}
}
