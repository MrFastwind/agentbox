package instance

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
	"agentbox/internal/policy"
)

const (
	maxCloneBytes = 256 << 20 // 256 MiB
	maxCloneFiles = 10000
)

// CloneConfig replaces an instance's config directory with a snapshot of the
// agent's host configuration. It uses policy.ClonePlan, so the same allow-list,
// symlink bounds and deny-list apply as in a live run. Credential-shaped JSON is
// sanitized; a file that cannot be sanitized is skipped with a warning (or
// fails under --strict-config).
//
// The replacement is staged in config.new and renamed into place, so a failed
// clone leaves the previous config intact. The persistent HOME is never touched.
func (s *Store) CloneConfig(inst *Instance, def agent.Definition, resolver *policy.Resolver, strict bool) ([]string, error) {
	seeds, mounts, refusals := resolver.ClonePlan(def, strict)
	var warnings []string
	for _, ref := range refusals {
		if ref.Fatal {
			return warnings, fmt.Errorf("%s", ref.String())
		}
		warnings = append(warnings, ref.String())
	}

	tmp := filepath.Join(inst.Dir, configDirName+".new")
	if err := os.RemoveAll(tmp); err != nil {
		return warnings, err
	}
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return warnings, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmp)
		}
	}()

	manifest := make([]ManifestEntry, 0, len(seeds)+len(mounts))
	budget := &cloneBudget{}
	for _, seed := range seeds {
		rel := filepath.FromSlash(seed.Rel)
		if !filepath.IsLocal(rel) {
			return warnings, fmt.Errorf("seed %q escapes the instance config", seed.Rel)
		}
		dst := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return warnings, err
		}
		if err := budget.add(len(seed.Data)); err != nil {
			return warnings, err
		}
		if err := os.WriteFile(dst, seed.Data, 0o600); err != nil {
			return warnings, err
		}
		manifest = append(manifest, ManifestEntry{
			Rel:         filepath.ToSlash(rel),
			Size:        len(seed.Data),
			SHA256:      fsx.SHA256Hex(seed.Data),
			Transform:   seed.Transform,
			RemovedKeys: seed.RemovedKeys,
			Origin:      "seed",
		})
	}

	seen := map[string]bool{}
	for _, mount := range mounts {
		rel := path.Base(mount.Dest)
		if rel == "." || rel == "/" || rel == "" {
			return warnings, fmt.Errorf("cannot clone mount %s: no directory name", mount.Dest)
		}
		if seen[rel] {
			return warnings, fmt.Errorf("cannot clone mount %s: duplicate destination name %q", mount.Dest, rel)
		}
		seen[rel] = true
		dst := filepath.Join(tmp, rel)
		if err := copyPath(mount.Host, dst, rel, mount.Origin, def.DeniedNames, strict, budget, &warnings, &manifest); err != nil {
			return warnings, err
		}
	}

	configPath := filepath.Join(inst.Dir, configDirName)
	if err := checkDir(configPath); err != nil {
		return warnings, fmt.Errorf("refusing to replace instance config: %w", err)
	}
	old := configPath + ".old"
	if err := os.RemoveAll(old); err != nil {
		return warnings, err
	}
	if err := os.Rename(configPath, old); err != nil {
		return warnings, err
	}
	if err := os.Rename(tmp, configPath); err != nil {
		_ = os.Rename(old, configPath)
		return warnings, err
	}
	cleanup = false
	_ = os.RemoveAll(old)

	inst.Meta.Source = Source{
		ConfigDir: def.ConfigDir,
		ClonedAt:  time.Now().UTC(),
		Files:     manifest,
	}
	if err := writeYAML(filepath.Join(inst.Dir, metadataFileName), inst.Meta); err != nil {
		return warnings, err
	}
	return warnings, nil
}

type cloneBudget struct {
	bytes int64
	files int
}

func (b *cloneBudget) add(n int) error {
	b.bytes += int64(n)
	b.files++
	if b.bytes > maxCloneBytes {
		return fmt.Errorf("instance config clone exceeds %d MiB", maxCloneBytes>>20)
	}
	if b.files > maxCloneFiles {
		return fmt.Errorf("instance config clone exceeds %d files", maxCloneFiles)
	}
	return nil
}

// copyPath copies a file or directory tree without following symlinks. Nested
// symlinks are skipped: a config tree is not an invitation to reach the rest of
// the host, and policy has already resolved the top-level entries it admitted.
func copyPath(src, dst, rel, origin string, denied []string, strict bool, budget *cloneBudget, warnings *[]string, manifest *[]ManifestEntry) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		*warnings = append(*warnings, fmt.Sprintf("skipping symlink %s: symlinks inside a cloned config are not followed", src))
		return nil
	case fi.IsDir():
		if err := os.Mkdir(dst, 0o700); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := entry.Name()
			if policy.MatchesDeniedName(name, denied) {
				*warnings = append(*warnings, fmt.Sprintf("skipping denied name %s in cloned config", name))
				continue
			}
			if err := copyPath(filepath.Join(src, name), filepath.Join(dst, name), path.Join(rel, name), origin, denied, strict, budget, warnings, manifest); err != nil {
				return err
			}
		}
		return nil
	case fi.Mode().IsRegular():
		raw, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		out := raw
		transform := agent.Identity{}.Name()
		var removed []string
		if strings.HasSuffix(strings.ToLower(fi.Name()), ".json") {
			out, removed, err = (agent.StripCredentialKeys{}).Apply(raw)
			if err != nil {
				if strict {
					return fmt.Errorf("sanitizing %s: %w", src, err)
				}
				*warnings = append(*warnings, fmt.Sprintf("skipping %s: %v", src, err))
				return nil
			}
			paths, err := agent.CredentialKeyPaths(out)
			if err != nil {
				if strict {
					return fmt.Errorf("checking %s: %w", src, err)
				}
				*warnings = append(*warnings, fmt.Sprintf("skipping %s: %v", src, err))
				return nil
			}
			if len(paths) > 0 {
				if strict {
					return fmt.Errorf("%s still contains credential-shaped keys: %s", src, strings.Join(paths, ", "))
				}
				*warnings = append(*warnings, fmt.Sprintf("skipping %s: credential-shaped keys remain: %s", src, strings.Join(paths, ", ")))
				return nil
			}
			transform = (agent.StripCredentialKeys{}).Name()
		}
		if err := budget.add(len(out)); err != nil {
			return err
		}
		if err := os.WriteFile(dst, out, 0o600); err != nil {
			return err
		}
		*manifest = append(*manifest, ManifestEntry{
			Rel:         filepath.ToSlash(rel),
			Size:        len(out),
			SHA256:      fsx.SHA256Hex(out),
			Transform:   transform,
			RemovedKeys: removed,
			Origin:      origin,
		})
		return nil
	default:
		*warnings = append(*warnings, fmt.Sprintf("skipping %s: not a regular file or directory", src))
		return nil
	}
}
