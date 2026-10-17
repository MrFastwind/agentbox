package policy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"agentbox/internal/agent"
)

// parseMount accepts SRC:DST[:ro|rw]. A colon inside a path is not supported;
// that is a documented limitation rather than a silent misparse.
func parseMount(raw string) (src, dst string, access Access, err error) {
	parts := strings.Split(raw, ":")
	switch len(parts) {
	case 2:
		return parts[0], parts[1], RO, nil
	case 3:
		switch parts[2] {
		case "ro":
			return parts[0], parts[1], RO, nil
		case "rw":
			return parts[0], parts[1], RW, nil
		default:
			return "", "", 0, fmt.Errorf("invalid access mode %q (want ro or rw)", parts[2])
		}
	default:
		return "", "", 0, fmt.Errorf("expected SRC:DST[:ro|rw]")
	}
}

// deniedName matches a filename against never-mount patterns.
func deniedName(name string, patterns []string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, name); err == nil && ok {
			return true
		}
	}
	return false
}

func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if within(pre, p) {
			return true
		}
	}
	return false
}

// explicitMount resolves and validates one --mount argument against the same
// deny-list the launch directory obeys.
func (r *Resolver) explicitMount(deny DenyList, raw string) (ResolvedMount, Refusal, bool) {
	src, dst, access, err := parseMount(raw)
	if err != nil {
		return ResolvedMount{}, refusal(RefusalMount, raw, err.Error()), false
	}
	if !filepath.IsAbs(dst) {
		return ResolvedMount{}, refusal(RefusalMount, raw, "destination must be an absolute container path"), false
	}
	abs, err := r.FS.Abs(src)
	if err != nil {
		return ResolvedMount{}, refusal(RefusalMount, src, "cannot resolve: "+err.Error()), false
	}
	resolved, err := r.FS.EvalSymlinks(abs)
	if err != nil {
		return ResolvedMount{}, refusal(RefusalMount, src, "cannot resolve: "+err.Error()), false
	}
	if err := deny.ValidateMount(resolved); err != nil {
		return ResolvedMount{}, refusal(RefusalMount, src, err.Error()), false
	}
	return ResolvedMount{Host: resolved, Dest: dst, Access: access, Origin: "extra"}, Refusal{}, true
}

// agentConfigMounts mounts an agent's configuration directory read-only, one
// top-level entry at a time.
//
// Mounting per entry rather than mounting the directory is what gives the
// "~/.config/**/auth.json" rule teeth: a credential file can actually be
// omitted, instead of being mounted and then described in documentation as
// though it were not.
//
// Symlinks are the other half. A naive directory mount leaves a dangling link
// inside the container; blindly following one lets a config directory point the
// sandbox at an attacker-chosen host path.
//
// Two bounds therefore apply to a followed link. Its target must sit under an
// allowed prefix — checked against the path the configuration actually wrote as
// well as against the resolved real path, because a home directory legitimately
// contains symlinks out to other volumes (~/media -> /run/media/...), which
// would otherwise resolve outside realpath(home) and be refused — and it must
// pass the same deny-list the launch directory obeys, so that a link into
// ~/.ssh is refused even though it is "inside home".
//
// A link that fails either bound is NOT followed. That is recorded as a warning
// and the entry is skipped rather than aborting the run: not mounting a path is
// always safe, and a link out of the config directory (a skills directory
// living on another volume, say) is a legitimate layout that should not make
// the sandbox unusable. The outcome is visible in doctor, on stderr, and in the
// audit log.
func (r *Resolver) agentConfigMounts(def agent.Definition, deny DenyList) ([]ResolvedMount, []Refusal) {
	dir, err := r.FS.EvalSymlinks(def.ConfigDir)
	if err != nil {
		return nil, []Refusal{refusal(RefusalAgent, def.ConfigDir,
			"cannot resolve agent configuration directory: "+err.Error())}
	}

	var mounts []ResolvedMount
	var refusals []Refusal

	// Two prefix sets are consulted when a config entry turns out to be a
	// symlink.
	//
	// The resolved prefixes are the real paths, so a link cannot dress up an
	// escaping target as a benign string. The logical prefixes are the paths
	// as the configuration wrote them, which still matters because a home
	// directory may contain symlinks out to other volumes: a home-relative
	// link then resolves outside realpath(home) while remaining an ordinary
	// path inside the user's home.
	logicalPrefixes := make([]string, 0, len(def.SymlinkTargetPrefixes))
	resolvedPrefixes := make([]string, 0, len(def.SymlinkTargetPrefixes))
	for _, p := range def.SymlinkTargetPrefixes {
		logicalPrefixes = append(logicalPrefixes, filepath.Clean(p))
		if resolved, err := r.FS.EvalSymlinks(p); err == nil {
			p = resolved
		}
		resolvedPrefixes = append(resolvedPrefixes, p)
	}

	entries, err := r.FS.ReadDir(dir)
	if err != nil {
		return nil, []Refusal{refusal(RefusalAgent, dir,
			"cannot read agent configuration directory: "+err.Error())}
	}

	for _, e := range entries {
		name := e.Name()
		src := filepath.Join(dir, name)
		dest := path.Join(def.ConfigDirInContainer, name)

		if deniedName(name, def.DeniedNames) {
			refusals = append(refusals, warn(RefusalMount, src,
				"not mounted: matches the never-mount rule"))
			continue
		}

		if e.Type()&os.ModeSymlink != 0 {
			target, err := r.FS.EvalSymlinks(src)
			if err != nil {
				refusals = append(refusals, warn(RefusalSymlink, src,
					"not followed: dangling symlink ("+err.Error()+")"))
				continue
			}
			if !r.symlinkWithinPrefixes(src, target, logicalPrefixes, resolvedPrefixes) {
				refusals = append(refusals, warn(RefusalSymlink, src,
					fmt.Sprintf("not followed: target %s is outside the allowed prefixes (%s); "+
						"the entry is skipped, not mounted", target, strings.Join(resolvedPrefixes, ", "))))
				continue
			}
			// The prefix bound only says "inside the user's own space", which
			// includes ~/.ssh. The deny-list is what actually separates
			// configuration from credentials, so a followed target obeys the
			// same rule the launch directory obeys.
			if err := deny.ValidateMount(target); err != nil {
				refusals = append(refusals, warn(RefusalSymlink, src,
					"not followed: target is deny-listed ("+err.Error()+")"))
				continue
			}
			mounts = append(mounts, ResolvedMount{
				Host: target, Dest: dest, Access: RO, Origin: "symlink",
			})
			continue
		}

		// A mounted configuration file may still carry credential-shaped keys.
		// The entry is mounted read-only because it is the agent's own
		// configuration, but the assertion is recorded so the boundary is
		// auditable rather than assumed. This is what catches files such as
		// cli.json / service.json, whose 0600 mode contradicts the "static
		// config only" assumption a directory mount would rest on.
		if !e.IsDir() && strings.HasSuffix(name, ".json") {
			if data, err := r.FS.ReadFile(src); err == nil {
				if paths, err := agent.CredentialKeyPaths(data); err == nil && len(paths) > 0 {
					reason := "carries credential-shaped keys: " + joinPaths(paths)
					if r.Strict {
						refusals = append(refusals, refusal(RefusalMount, src, "refused in strict mode: "+reason))
						continue
					}
					refusals = append(refusals, warn(RefusalMount, src,
						"mounted read-only, but "+reason))
				}
			}
		}

		mounts = append(mounts, ResolvedMount{
			Host: src, Dest: dest, Access: RO, Origin: "agent-config",
		})
	}

	return mounts, refusals
}

// symlinkWithinPrefixes decides whether a followed config symlink may be
// mounted, and is the whole of the "where may a config link point" rule.
//
// It accepts a link whose resolved target is under a resolved prefix — the
// original, strict reading — or a link whose own target as written is under a
// logical prefix. The second arm is what makes an ordinary home-relative link
// work when the home directory reaches outside itself through a symlink
// (~/media -> /run/media/...): the link says "/home/u/...", which is inside the
// user's home as far as the configuration is concerned, even though resolving
// it lands on another volume.
//
// Passing this bound does not by itself permit the mount: the resolved target
// must still clear the deny-list, which is what keeps ~/.ssh out on the grounds
// that it is a credential directory rather than merely being under home.
func (r *Resolver) symlinkWithinPrefixes(link, resolvedTarget string, logicalPrefixes, resolvedPrefixes []string) bool {
	if underAny(resolvedTarget, resolvedPrefixes) {
		return true
	}
	raw, err := r.FS.Readlink(link)
	if err != nil {
		return false
	}
	logical := raw
	if !filepath.IsAbs(logical) {
		logical = filepath.Join(filepath.Dir(link), logical)
	}
	return underAny(filepath.Clean(logical), logicalPrefixes)
}
