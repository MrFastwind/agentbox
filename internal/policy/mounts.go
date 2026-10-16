package policy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"container-agent/internal/agent"
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
// A symlink whose target lands outside the allowed prefixes is therefore NOT
// followed. That is recorded as a warning and the entry is skipped rather than
// aborting the run: not mounting a path is always safe, and a link out of the
// config directory (a skills directory living on another volume, say) is a
// legitimate layout that should not make the sandbox unusable. The outcome is
// visible in doctor and in the audit log.
func (r *Resolver) agentConfigMounts(def agent.Definition) ([]ResolvedMount, []Refusal) {
	dir, err := r.FS.EvalSymlinks(def.ConfigDir)
	if err != nil {
		return nil, []Refusal{refusal(RefusalAgent, def.ConfigDir,
			"cannot resolve agent configuration directory: "+err.Error())}
	}

	var mounts []ResolvedMount
	var refusals []Refusal

	// Resolve the allowed prefixes up front, so comparison happens on real
	// paths rather than on strings that a symlink can dress up.
	prefixes := make([]string, 0, len(def.SymlinkTargetPrefixes))
	for _, p := range def.SymlinkTargetPrefixes {
		if resolved, err := r.FS.EvalSymlinks(p); err == nil {
			p = resolved
		}
		prefixes = append(prefixes, p)
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
			if !underAny(target, prefixes) {
				refusals = append(refusals, warn(RefusalSymlink, src,
					fmt.Sprintf("not followed: target %s is outside the allowed prefixes (%s); "+
						"the entry is skipped, not mounted", target, strings.Join(prefixes, ", "))))
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
