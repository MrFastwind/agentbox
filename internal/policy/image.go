package policy

import (
	"fmt"
	"regexp"
	"strings"
)

var agentVersionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)
var imageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidateImageRef reports whether ref is a fully-qualified image name.
//
// Podman does not default an unqualified name to Docker Hub the way Docker
// does. It resolves the name against the host's unqualified-search-registries
// list, which is not configured here and differs per machine. The same
// unqualified string therefore selects a different image on a different host —
// exactly the ambiguity a sandbox must not have. So an override must name its
// registry: host[:port]/namespace/name[:tag|@digest].
//
// The rule mirrors podman's own: the first path component is a registry host
// only when it contains a dot or a colon, or is "localhost". Anything else is a
// namespace under an unspecified registry and is refused.
// ValidateAgentVersion accepts only a numeric three-part release version.
// Agent images are built from reviewed pins; "latest" must never enter a
// ResolvedSpec, where it would make two runs disagree about what was launched.
func ValidateAgentVersion(version string) error {
	if !agentVersionPattern.MatchString(version) {
		return fmt.Errorf("agent version %q is not a stable three-part version", version)
	}
	return nil
}

// ValidateImageDigest accepts the only digest form emitted by podman here.
func ValidateImageDigest(digest string) error {
	if !imageDigestPattern.MatchString(digest) {
		return fmt.Errorf("image digest %q is not a sha256 digest", digest)
	}
	return nil
}

func ValidateImageRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("image reference is empty")
	}
	if strings.ContainsAny(ref, " \t\r\n") {
		return fmt.Errorf("image reference %q contains whitespace", ref)
	}
	if strings.Contains(ref, "://") {
		return fmt.Errorf("image reference %q must not include a scheme", ref)
	}

	// Strip a digest before looking for the registry. Only sha256 digests are
	// recognised; anything else is a typo worth surfacing.
	name := ref
	if i := strings.Index(name, "@"); i >= 0 {
		if !strings.HasPrefix(name[i+1:], "sha256:") {
			return fmt.Errorf("image reference %q has an unsupported digest", ref)
		}
		name = name[:i]
	}

	slash := strings.Index(name, "/")
	if slash <= 0 {
		return fmt.Errorf("image reference %q is unqualified: name its registry, e.g. docker.io/library/<name> or localhost/<name>", ref)
	}
	host := name[:slash]
	if !strings.ContainsAny(host, ".:") && host != "localhost" {
		return fmt.Errorf("image reference %q is unqualified: %q is not a registry host, e.g. docker.io/%s or localhost/%s", ref, host, ref, ref)
	}
	return nil
}
