package cmd

import (
	"os/exec"
	"strings"

	"agentbox/internal/agent"
	"agentbox/internal/policy"
	"agentbox/internal/session"
)

// Seams. These exist so the command-line layer — argument precedence, config
// merging, subcommand dispatch — can be tested without podman on the machine or
// a container to run. Each defaults to the real implementation.

// execCommand is exec.Command, used by the podman-invoking paths.
var execCommand = exec.Command

// ensureImage builds default images if missing.
var ensureImage = ensureImageAvailable

// runSession boots a resolved request. The default is session.Options.Boot.
var runSession = func(o session.Options, def agent.Definition, req policy.Request) (int, error) {
	if !o.PrintArgv {
		if err := ensureImage(req.Image, def, req.NoUserConfig); err != nil {
			return 1, err
		}
	}
	return o.Boot(def, req)
}

// podmanContainerStatus reports a container's state. The bool is "podman found
// the container", not "the command succeeded": a missing container and an
// unavailable runtime are both treated as absent by callers that are about to
// start or remove one.
var podmanContainerStatus = func(name string) (string, bool) {
	out, err := execCommand("podman", "inspect", "--format", "{{.State.Status}}", name).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// podmanRemove removes a named container, including a running one.
var podmanRemove = func(name string) error {
	return execCommand("podman", "rm", "-f", name).Run()
}
