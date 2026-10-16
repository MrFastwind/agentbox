package policy

import (
	"fmt"
	"strings"
)

// EgressPolicy decides the container's network mode.
//
// This exists as a seam, not as a switch: the choice of mode is the one R1-adjacent
// decision that is genuinely still open, and modelling it as an interface means
// selecting a different default — or dropping in an allow-listing egress proxy —
// is a new implementation rather than a rewrite of the argv builder.
type EgressPolicy interface {
	Decide(requested string) (NetworkDecision, error)
}

// DefaultEgress is the shipped policy.
//
// The default is pasta, not host. Under rootless podman, --network=host gives
// the container an interface onto the physical LAN and, on this class of host,
// the tailnet as well, plus shared host loopback — which would make a
// loopback-bound podman API reachable from inside the sandbox. pasta provides
// outbound connectivity (so the agent can reach its model provider at all)
// without the container ever getting a tap onto those networks.
//
// pasta is podman's rootless default. slirp4netns is accepted for older podman
// but was removed in podman 6, where selecting it fails at container start;
// hanging onto it as the default would make the tool fail on current systems.
//
// "none" is strictly more isolated and is available explicitly; it makes the
// agent unable to reach its provider, which is the right trade for an
// untrusted repository.
type DefaultEgress struct{}

var validNetworkModes = map[string]bool{
	"none":        true,
	"pasta":       true,
	"private":     true,
	"slirp4netns": true, // legacy: accepted, removed in podman 6
	"host":        true,
}

const defaultNetworkMode = "pasta"

func (DefaultEgress) Decide(requested string) (NetworkDecision, error) {
	mode := strings.TrimSpace(requested)
	if mode == "" {
		mode = defaultNetworkMode
	}
	if !validNetworkModes[mode] {
		return NetworkDecision{}, fmt.Errorf("unknown network mode %q (valid: none, pasta, private, slirp4netns, host)", mode)
	}
	d := NetworkDecision{Mode: mode}
	switch mode {
	case "host":
		d.Warning = "host networking gives the sandbox an interface onto the LAN and any tailnet, and shares host loopback (a loopback-bound podman API would be reachable from inside)"
	case "slirp4netns":
		d.Warning = "slirp4netns was removed in podman 6 and will fail at container start; use pasta"
	}
	return d, nil
}
