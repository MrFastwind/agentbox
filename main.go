package main

import (
	"os"

	"agentbox/cmd"
)

func main() {
	os.Exit(cmd.Main(os.Args[1:]))
}
