package policy

import (
	"fmt"
	"strings"
)

// HostnamePrefix is prepended to the agent name to form the default hostname
// of the sandbox. The name is visible to everything inside the container
// (gethostname(2), /etc/hostname), which is the point: an agent that reports
// its hostname reports which box it is running in.
const HostnamePrefix = "agentbox-"

// DefaultHostname is the hostname of a run the user did not give one:
// "agentbox-<agent>".
func DefaultHostname(agentName string) string {
	return HostnamePrefix + agentName
}

// ValidateHostname reports whether h can be used as a container hostname.
//
// Podman hands the value to sethostname(2), so the Linux limit (HOST_NAME_MAX,
// 64 bytes) applies to the whole name, and each dot-separated label must be an
// RFC 1123 name: alphanumeric ends, alphanumeric or hyphen inside, at most 63
// characters. Anything else is refused here rather than surfacing as an
// opaque runtime failure after the sandbox has begun to start.
func ValidateHostname(h string) error {
	if h == "" {
		return fmt.Errorf("hostname is empty")
	}
	if len(h) > 64 {
		return fmt.Errorf("hostname is %d bytes; the limit is 64", len(h))
	}
	for _, label := range strings.Split(h, ".") {
		if err := validateHostnameLabel(label); err != nil {
			return fmt.Errorf("hostname %q: %w", h, err)
		}
	}
	return nil
}

func validateHostnameLabel(label string) error {
	if label == "" {
		return fmt.Errorf("empty label")
	}
	if len(label) > 63 {
		return fmt.Errorf("label is %d bytes; the limit is 63", len(label))
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		switch {
		case alnum:
		case c == '-' && i > 0 && i < len(label)-1:
		default:
			return fmt.Errorf("label %q contains byte %q; only letters, digits and inner hyphens are allowed", label, string(c))
		}
	}
	return nil
}
