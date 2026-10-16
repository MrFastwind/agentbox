package cmd

import (
	"fmt"
	"os"
	"strings"

	"agentbox/internal/agent"
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

	fmt.Println("agents")
	for _, name := range reg.Names() {
		def, err := reg.Get(name)
		if err != nil {
			continue
		}
		fmt.Printf("  %s\n", name)
		fmt.Printf("    image         %s\n", def.Image)
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
		if len(def.EnvAllowlist) > 0 {
			fmt.Printf("    env allowlist %s\n", strings.Join(def.EnvAllowlist, ", "))
		}
	}
	fmt.Println()

	// The mode question, stated plainly: it must never be ambiguous whether the
	// user's own configuration was wired in.
	fmt.Println("modes")
	fmt.Println("  without --no-user-config: host agent configuration is wired in as declared above")
	fmt.Println("  with    --no-user-config: no host path is read, mounted or seeded for any agent")
	fmt.Println()

	fmt.Println("network")
	fmt.Println("  default: pasta (outbound only; no LAN, tailnet or host loopback)")
	fmt.Println("  none   : available with --network=none for untrusted repositories")
	fmt.Println("  host   : available but discouraged; exposes the LAN, any tailnet and host loopback")
	fmt.Println()

	fmt.Println("workspace")
	fmt.Println("  the launch directory is writable by default: blast radius is the project tree")

	return 0
}

func podmanLine(args ...string) string {
	out, err := execCommand("podman", args...).Output()
	if err != nil {
		return "unavailable (" + err.Error() + ")"
	}
	return strings.TrimSpace(string(out))
}
