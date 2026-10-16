package policy

import (
	"fmt"

	"agentbox/internal/fsx"
)

// userOrigins are the mount origins that reflect a decision about a host path
// the user or their project controls. The session appends "state" and "seed"
// mounts after resolution; those are program-owned and are not re-checked here.
var userOrigins = map[string]bool{
	"launch-dir":   true,
	"agent-config": true,
	"symlink":      true,
	"extra":        true,
}

// Revalidate re-checks a resolved spec immediately before it is handed to the
// runtime.
//
// Resolve already resolves symlinks and validates the deny-list, but the
// filesystem can change between that decision and the moment podman opens the
// path — a classic time-of-check/time-of-use gap. This second pass refuses:
//
//   - a mount whose host path no longer resolves to the path that was validated
//     (a symlink was planted or swapped after validation), and
//   - a read-only mount that now sits inside a writable mount, because a
//     writable parent lets the sandbox replace the read-only target after the
//     check.
//
// It is deliberately conservative: any change to a validated path is a refusal,
// not a warning.
func Revalidate(spec *ResolvedSpec, fs fsx.FS) error {
	var writable []string
	for _, m := range spec.Mounts {
		if !userOrigins[m.Origin] || m.Access != RW {
			continue
		}
		real, err := fs.EvalSymlinks(m.Host)
		if err != nil {
			return fmt.Errorf("re-validating writable mount %s: %w", m.Host, err)
		}
		if real != m.Host {
			return fmt.Errorf("mount %s now resolves to %s; refusing", m.Host, real)
		}
		writable = append(writable, real)
	}

	for _, m := range spec.Mounts {
		if !userOrigins[m.Origin] {
			continue
		}
		real, err := fs.EvalSymlinks(m.Host)
		if err != nil {
			return fmt.Errorf("re-validating mount %s: %w", m.Host, err)
		}
		if real != m.Host {
			return fmt.Errorf("mount %s now resolves to %s; refusing", m.Host, real)
		}
		if m.Access == RW {
			continue
		}
		for _, w := range writable {
			if within(w, real) {
				return fmt.Errorf("read-only mount %s now sits inside writable mount %s; refusing", real, w)
			}
		}
	}
	return nil
}

// Revalidate re-checks spec against this resolver's filesystem.
func (r *Resolver) Revalidate(spec *ResolvedSpec) error {
	return Revalidate(spec, r.FS)
}
