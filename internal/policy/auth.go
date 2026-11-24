package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
)

// maxAuthFileSize bounds a credential file read. Auth files are small JSON or
// token blobs; the cap exists so a hostile or accidental large file cannot turn
// an opt-in into a memory problem.
const maxAuthFileSize = 1 << 20

// collectAuth reads the allow-listed credential files for --user-auth.
//
// This is deliberately a separate path from collectSeeds. Seed files are
// configuration that may carry credentials by accident, so they are transformed
// and content-scanned. Auth files are credentials by definition: the only
// boundary that can make them safe is the registry allow-list plus the user's
// explicit opt-in, and scanning them for credential-shaped keys would simply
// refuse every one.
func collectAuth(fs fsx.FS, home string, def agent.Definition) ([]AuthFile, []Refusal) {
	var auth []AuthFile
	var refusals []Refusal

	for _, spec := range def.AuthFiles {
		if !validAuthRel(spec.Rel) || !validAuthRel(spec.ContainerRel) {
			refusals = append(refusals, refusal(RefusalAuth, spec.Rel,
				"auth path is not a clean home-relative path"))
			continue
		}

		full := filepath.Join(home, filepath.FromSlash(spec.Rel))
		fi, err := fs.Lstat(full)
		if err != nil {
			if os.IsNotExist(err) {
				refusals = append(refusals, warn(RefusalAuth, spec.Rel, "not present; skipped"))
			} else {
				refusals = append(refusals, refusal(RefusalAuth, spec.Rel,
					"could not be inspected: "+err.Error()))
			}
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			refusals = append(refusals, refusal(RefusalAuth, spec.Rel,
				"is a symlink; refusing to follow a credential file"))
			continue
		}
		if !fi.Mode().IsRegular() {
			refusals = append(refusals, refusal(RefusalAuth, spec.Rel,
				"is not a regular file"))
			continue
		}
		if fi.Size() > maxAuthFileSize {
			refusals = append(refusals, refusal(RefusalAuth, spec.Rel,
				fmt.Sprintf("is %d bytes; limit is %d", fi.Size(), maxAuthFileSize)))
			continue
		}

		raw, err := fs.ReadFile(full)
		if err != nil {
			refusals = append(refusals, refusal(RefusalAuth, spec.Rel,
				"could not be read: "+err.Error()))
			continue
		}
		if len(raw) > maxAuthFileSize {
			refusals = append(refusals, refusal(RefusalAuth, spec.Rel,
				fmt.Sprintf("is %d bytes after reading; limit is %d", len(raw), maxAuthFileSize)))
			continue
		}

		auth = append(auth, AuthFile{
			SourceRel: spec.Rel,
			Rel:       spec.ContainerRel,
			Size:      len(raw),
			SHA256:    fsx.SHA256Hex(raw),
			Data:      raw,
		})
	}

	return auth, refusals
}

// validAuthRel keeps a registry entry from turning into an arbitrary path. The
// registry is code, not user input, but this is the same fail-closed check the
// rest of the policy layer applies to paths that reach the container.
func validAuthRel(p string) bool {
	if p == "" || filepath.IsAbs(p) {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(p))
	if clean == "." || clean == ".." {
		return false
	}
	return !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}
