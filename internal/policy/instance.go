package policy

import (
	"fmt"
	"path/filepath"
	"regexp"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
)

// instanceNameRE is deliberately narrower than podman's container-name rules:
// the name is also a directory component and part of the container hostname, so
// lowercase, no dots and no leading dash keeps all three unambiguous.
var instanceNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidateInstanceName checks the user-facing instance name. It is used before
// any path is joined, so a name can never introduce a separator or "..".
func ValidateInstanceName(name string) error {
	if name == "" {
		return fmt.Errorf("instance name is empty")
	}
	if !instanceNameRE.MatchString(name) {
		return fmt.Errorf("instance name %q must match [a-z0-9][a-z0-9_-]{0,31}", name)
	}
	return nil
}

// ValidateInstanceRoot checks the resolved instance store root. The store lives
// outside every protected prefix so its contents can be mounted; a root under
// ~/.local, for example, would be refused by the same deny-list that protects
// agent state, and failing at create time is clearer than failing at open.
func ValidateInstanceRoot(resolvedHome, root string) error {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) {
		return fmt.Errorf("instance root %q must be absolute", root)
	}
	if root == "/" {
		return fmt.Errorf("refusing to use the filesystem root as the instance store")
	}
	if root == filepath.Clean(resolvedHome) {
		return fmt.Errorf("refusing to use the home directory as the instance store")
	}
	deny := NewDenyList(resolvedHome)
	if err := deny.ValidateMount(root); err != nil {
		return fmt.Errorf("instance store %s: %w", root, err)
	}
	return nil
}

// ValidateInstancePaths is the create-time check: the name is safe and the
// store root is a place whose contents policy is willing to mount.
func ValidateInstancePaths(resolvedHome, root, name string) error {
	if err := ValidateInstanceName(name); err != nil {
		return err
	}
	return ValidateInstanceRoot(resolvedHome, root)
}

// validateInstanceDir requires a real, owner-only directory. A symlink here is
// the host-write trap: a previous agent run could plant home/.config as a link
// to the host's ~/.ssh, and MkdirAll would follow it.
func validateInstanceDir(fs fsx.FS, dir string) error {
	real, err := fs.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve: %w", err)
	}
	if real != dir {
		return fmt.Errorf("resolves to %s; refusing a symlinked instance directory", real)
	}
	fi, err := fs.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("is not a directory")
	}
	if fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("mode is %04o; instance directories must be 0700", fi.Mode().Perm())
	}
	return nil
}

// ClonePlan reports what cloning an agent's host configuration would copy. It
// uses the same allow-list, transforms, deny-list and symlink decisions as a
// live run; it only needs the host definition, not a launch directory.
func (r *Resolver) ClonePlan(def agent.Definition, strict bool) ([]SeededFile, []ResolvedMount, []Refusal) {
	deny := r.denyList()
	switch def.Strategy {
	case agent.StrategyMount:
		mounts, refs := r.agentConfigMountsFrom(def, def.ConfigDir, deny, def.SymlinkTargetPrefixes)
		return nil, mounts, refs
	case agent.StrategySeed:
		seeds, refs := collectSeedsFrom(r.FS, def, def.ConfigDir, strict)
		return seeds, nil, refs
	default:
		return nil, nil, nil
	}
}
