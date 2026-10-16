package policy

import (
	"path/filepath"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
)

// collectSeeds reads the allow-listed seed files for a StrategySeed agent.
//
// Two independent checks apply to every file, because either one alone would be
// insufficient:
//
//  1. the allow-list in the registry decides which files are read at all;
//  2. every file that is read is then content-scanned for credential-shaped
//     keys, so a file that is safe by name but not by content still fails closed.
//
// A file whose keys are removed by its transform is fine: the removal is
// recorded, so doctor and --print-argv can show exactly what was stripped.
func collectSeeds(fs fsx.FS, def agent.Definition, strict bool) ([]SeededFile, []Refusal) {
	var seeds []SeededFile
	var refusals []Refusal

	for _, spec := range def.SeedFiles {
		full := filepath.Join(def.ConfigDir, spec.Rel)

		raw, err := fs.ReadFile(full)
		if err != nil {
			if spec.Required {
				refusals = append(refusals, refusal(RefusalSeed, full, "required config file could not be read: "+err.Error()))
			} else {
				refusals = append(refusals, warn(RefusalSeed, full, "not present; skipped"))
			}
			continue
		}

		out, removed, err := spec.Transform.Apply(raw)
		if err != nil {
			refusals = append(refusals, refusal(RefusalSeed, full,
				"transform "+spec.Transform.Name()+" failed: "+err.Error()))
			continue
		}

		// Content assertion: applied to the transformed bytes.
		paths, scanErr := agent.CredentialKeyPaths(out)
		switch {
		case scanErr != nil:
			if strict {
				refusals = append(refusals, refusal(RefusalSeed, full,
					"refused in strict mode: not valid JSON, so the credential check could not run"))
				continue
			}
			refusals = append(refusals, warn(RefusalSeed, full,
				"not valid JSON, so the credential check could not run; seeding unassayed"))
		case len(paths) > 0:
			refusals = append(refusals, refusal(RefusalSeed, full,
				"credential-shaped keys survived the transform: "+joinPaths(paths)))
			continue
		}

		seeds = append(seeds, SeededFile{
			Rel:         spec.Rel,
			Size:        len(out),
			Mode:        0o600,
			SHA256:      fsx.SHA256Hex(out),
			Transform:   spec.Transform.Name(),
			RemovedKeys: removed,
			Data:        out,
		})
	}

	return seeds, refusals
}

func joinPaths(ps []string) string {
	out := ""
	for i, p := range ps {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
