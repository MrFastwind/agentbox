package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

// DenyList is the set of host paths that must never become a mount. It is
// applied to the launch directory and to every explicit --mount, so that the
// auto-mounted workspace cannot bypass the rules that explicit mounts obey.
//
// Matching is against resolved real paths, never the literal string the user
// typed: matching the literal is trivially bypassed with a symlink.
type DenyList struct {
	Home     string
	Prefixes []string
}

// sensitiveRel are paths under the home directory whose exposure would hand the
// sandbox credentials or control of other systems.
var sensitiveRel = []string{
	".ssh",
	".aws",
	".gnupg",
	".pi",
	".local",
	".docker",
	".kube",
	".netrc",
	".git-credentials",
	".npmrc",
	".pypirc",
	".password-store",
	".mozilla",
	".config/gh",
	".config/gcloud",
	".config/opencode",
	".config/containers",
	".config/podman",
}

// systemPrefixes are host paths that are never a legitimate project directory.
//
// /run is deliberately not listed wholesale: /run/media and /run/mount are
// ordinary locations for removable and network media, and a blanket rule there
// refuses legitimate project directories. What must not be reachable is the
// per-user runtime directory — sockets, ssh-agent, the podman API — so those are
// named specifically.
var systemPrefixes = []string{
	"/etc",
	"/proc",
	"/sys",
	"/dev",
	"/boot",
	"/root",
	"/run/user",
	"/run/podman",
	"/run/containers",
	"/run/secrets",
	"/var/run/user",
	"/var/run/podman",
	"/var/lib/podman",
}

func NewDenyList(resolvedHome string) DenyList {
	home := filepath.Clean(resolvedHome)
	prefixes := make([]string, 0, len(sensitiveRel)+len(systemPrefixes))
	prefixes = append(prefixes, systemPrefixes...)
	for _, rel := range sensitiveRel {
		prefixes = append(prefixes, filepath.Join(home, rel))
	}
	return DenyList{Home: home, Prefixes: prefixes}
}

// within reports whether p is base or a descendant of base.
func within(base, p string) bool {
	base = strings.TrimSuffix(filepath.Clean(base), "/")
	if p == base {
		return true
	}
	return strings.HasPrefix(p, base+"/")
}

// Contains reports whether p sits inside a protected prefix.
func (d DenyList) Contains(p string) (string, bool) {
	for _, pre := range d.Prefixes {
		if within(pre, p) {
			return pre, true
		}
	}
	return "", false
}

// ValidateMount is the rule for anything that becomes a bind mount.
//
// Three refusals, all of which exist because the corresponding bypass was real:
//
//   - the filesystem root, and the home directory as a whole. "cd ~ && run"
//     otherwise mounts every credential file the user owns, with the deny-list
//     never consulted, because the launch directory was auto-mounted.
//   - a path inside a protected prefix (e.g. ~/.ssh/id_ed25519).
//   - a path that *contains* a protected prefix (e.g. /home/u, which contains
//     ~/.ssh). This is what makes an ancestor directory as unsafe as the
//     sensitive directory itself.
func (d DenyList) ValidateMount(p string) error {
	p = filepath.Clean(p)
	if p == "/" {
		return fmt.Errorf("refusing to mount the filesystem root")
	}
	if p == d.Home {
		return fmt.Errorf("refusing to mount the home directory as a whole; run from a project directory or pass --workdir")
	}
	for _, pre := range d.Prefixes {
		if within(pre, p) {
			return fmt.Errorf("refusing: it is inside protected path %s", pre)
		}
		if within(p, pre) {
			return fmt.Errorf("refusing: it contains protected path %s", pre)
		}
	}
	return nil
}
