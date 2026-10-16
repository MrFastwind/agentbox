package main

import (
	"os"

	"container-agent/cmd"
)

func main() {
	os.Exit(cmd.Main(os.Args[1:]))
}
