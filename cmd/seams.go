package cmd

import (
	"os/exec"

	"agentbox/internal/agent"
	"agentbox/internal/policy"
	"agentbox/internal/session"
)

// Seams. These exist so the command-line layer — argument precedence, config
// merging, subcommand dispatch — can be tested without podman on the machine or
// a container to run. Each defaults to the real implementation.

// execCommand is exec.Command, used by the podman-invoking paths.
var execCommand = exec.Command

// runSession boots a resolved request. The default is session.Options.Boot.
var runSession = func(o session.Options, def agent.Definition, req policy.Request) (int, error) {
	return o.Boot(def, req)
}
