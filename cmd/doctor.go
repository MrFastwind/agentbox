package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
	"agentbox/internal/instance"
	"agentbox/internal/policy"
	"agentbox/internal/update"
)

// runDoctor reports the facts a run depends on, and — importantly — which mode
// a given invocation would use and exactly which host paths would be read.
func runDoctor(args []string) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: locating home directory: %v\n", err)
		return 1
	}
	reg := agent.New(home)

	fmt.Println("agentbox doctor")
	fmt.Println()

	fmt.Println("runtime")
	fmt.Printf("  podman          %s\n", podmanLine("version", "--format", "{{.Client.Version}}"))
	fmt.Printf("  rootless        %s\n", podmanLine("info", "--format", "{{.Host.Security.Rootless}}"))
	fmt.Printf("  userns          %s\n", podmanLine("info", "--format", "{{.Host.IDMappings.UIDMap}}"))
	fmt.Println()

	fmt.Println("images")
	fmt.Printf("  build inputs    %s\n", imageSourceName())
	installed, stateErr := update.LoadState()
	if stateErr != nil {
		fmt.Printf("  installed       unavailable: %v\n", stateErr)
	} else if path, err := update.StatePath(); err == nil {
		fmt.Printf("  installed       %s\n", path)
	}
	fmt.Println()

	fmt.Println("agents")
	resolver := policy.NewResolver(fsx.Real{}, os.LookupEnv)
	for _, name := range reg.Names() {
		def, err := reg.Get(name)
		if err != nil {
			continue
		}
		fmt.Printf("  %s\n", name)
		image := def.Image
		version := "not installed"
		if stateErr == nil {
			if rec, ok := installed.For(name); ok {
				image = rec.Image
				version = rec.Version
			}
		}
		fmt.Printf("    image         %s\n", image)
		fmt.Printf("    agent version %s\n", version)
		fmt.Printf("    strategy      %s\n", def.Strategy)
		if def.ConfigDir == "" {
			fmt.Printf("    host config   (none read)\n")
		} else {
			state := "missing"
			if _, err := os.Stat(def.ConfigDir); err == nil {
				state = "present"
			}
			fmt.Printf("    host config   %s (%s)\n", def.ConfigDir, state)
		}
		fmt.Printf("    in container  %s\n", def.ConfigDirInContainer)
		if len(def.SeedFiles) > 0 {
			var names []string
			for _, s := range def.SeedFiles {
				names = append(names, s.Rel+" ["+s.Transform.Name()+"]")
			}
			fmt.Printf("    seeded files  %s\n", strings.Join(names, ", "))
		}
		if len(def.AuthFiles) > 0 {
			var names []string
			for _, a := range def.AuthFiles {
				state := "missing"
				if _, err := os.Stat(filepath.Join(home, filepath.FromSlash(a.Rel))); err == nil {
					state = "present"
				}
				names = append(names, a.Rel+" ("+state+")")
			}
			fmt.Printf("    user auth     %s\n", strings.Join(names, ", "))
		}
		if len(def.EnvAllowlist) > 0 {
			fmt.Printf("    env allowlist %s\n", strings.Join(def.EnvAllowlist, ", "))
		}
		// What would actually become a mount: which config links are followed,
		// and which are skipped and why. This is shown before any run because a
		// skipped link otherwise surfaces only in the audit log, or as the agent
		// failing to find its skills.
		if def.Strategy == agent.StrategyMount {
			decisions, notes := resolver.AgentConfigDecisions(def)
			for _, m := range decisions {
				if m.Origin == "symlink" {
					fmt.Printf("    link          %s -> %s\n", m.Host, m.Dest)
				}
			}
			for _, n := range notes {
				fmt.Printf("    note          %s\n", n.String())
			}
		}
	}
	fmt.Println()

	// The mode question, stated plainly: it must never be ambiguous whether the
	// user's own configuration was wired in.
	fmt.Println("modes")
	fmt.Println("  without --no-user-config: host agent configuration is wired in as declared above")
	fmt.Println("  with    --no-user-config: no host path is read, mounted or seeded for any agent")
	fmt.Println("  --user-auth             : copy only the allow-listed credential files above into the ephemeral HOME")
	fmt.Println()

	fmt.Println("network")
	fmt.Println("  default: pasta (outbound only; no LAN, tailnet or host loopback)")
	fmt.Println("  none   : available with --network=none for untrusted repositories")
	fmt.Println("  host   : available but discouraged; exposes the LAN, any tailnet and host loopback")
	fmt.Println()

	fmt.Println("workspace")
	fmt.Println("  the launch directory is writable by default: blast radius is the project tree")
	fmt.Println("  --read-only-workspace: mount the workspace read-only (agent cannot modify the project)")
	fmt.Println("  --workspace <subdir> : mount a subdirectory as the workspace instead of the launch directory")
	fmt.Println()

	fmt.Println("instances")
	if store, err := instance.OpenStore(); err != nil {
		fmt.Printf("  unavailable     %v\n", err)
	} else if entries, err := store.List(); err != nil {
		fmt.Printf("  unavailable     %v\n", err)
	} else if len(entries) == 0 {
		fmt.Println("  none            create one with `agentbox create NAME --agent opencode`")
	} else {
		for _, entry := range entries {
			if entry.Err != nil {
				fmt.Printf("  %-14s invalid: %v\n", entry.Name, entry.Err)
				continue
			}
			status := "-"
			if s, ok := podmanContainerStatus(entry.Instance.ContainerName()); ok {
				status = s
			}
			fmt.Printf("  %-14s agent=%s status=%s home=%s\n",
				entry.Name, entry.Instance.Config.Agent, status,
				map[bool]string{true: "persistent", false: "ephemeral"}[entry.Instance.Meta.PersistState])
		}
	}

	return 0
}

func podmanLine(args ...string) string {
	out, err := execCommand("podman", args...).Output()
	if err != nil {
		return "unavailable (" + err.Error() + ")"
	}
	return strings.TrimSpace(string(out))
}
