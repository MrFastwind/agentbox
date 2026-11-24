package cmd

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"agentbox/internal/agent"
	"agentbox/internal/audit"
	"agentbox/internal/cli"
	"agentbox/internal/config"
	"agentbox/internal/fsx"
	"agentbox/internal/policy"
	"agentbox/internal/session"
	"agentbox/internal/update"
)

func runRoot(inv cli.Invocation) int {
	fs := flag.NewFlagSet("agentbox", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(fs) }

	var (
		agentName    = fs.String("agent", "", "agent to launch (opencode, pi, claude, antigravity, shell)")
		workdir      = fs.String("workdir", "", "override the launch directory")
		image        = fs.String("image", "", "override the sandbox image (fully-qualified name required)")
		hostname     = fs.String("hostname", "", "container hostname (default agentbox-<agent>)")
		noUserConfig = fs.Bool("no-user-config", false, "read, mount and seed no host agent configuration")
		userAuth     = fs.Bool("user-auth", false, "copy the agent's allow-listed host credential files into the sandbox")
		network      = fs.String("network", "", "network mode: pasta (default), none, private, host")
		memory       = fs.String("memory", "", "memory limit (default 4g)")
		cpus         = fs.String("cpus", "", "CPU limit (default 2)")
		pidsLimit    = fs.Int("pids-limit", 0, "process count limit (default 2048)")
		workspace    = fs.String("workspace", "", "mount this subdirectory as the workspace instead of the launch directory")
		roWorkspace  = fs.Bool("read-only-workspace", false, "mount the workspace read-only")
		configPath   = fs.String("config", "", "project configuration file (never auto-discovered)")
		printArgv    = fs.Bool("print-argv", false, "print the podman argv and exit")
		auditLog     = fs.String("audit-log", "", "append a JSON decision record to this file")
		forceShell   = fs.Bool("shell", false, "run a shell in the agent's image instead of the agent")
		strictConfig = fs.Bool("strict-config", false, "refuse host configuration that carries credential-shaped keys instead of mounting it read-only")
	)

	var envs, mounts stringSlice
	fs.Var(&envs, "env", "pass one host environment variable (repeatable; allow-listed per agent)")
	fs.Var(&mounts, "mount", "extra mount SRC:DST[:ro|rw] (repeatable; deny-list validated)")

	var command []string
	if inv.Explicit {
		// "--" was used: every argument is a command to run in the container.
		command = inv.Args
	} else {
		if err := fs.Parse(inv.Args); err != nil {
			return 2
		}
		command = fs.Args()
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	var cfg *config.File
	if *configPath != "" {
		var err error
		cfg, err = config.Load(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 2
		}
	}

	// Precedence: explicit flag, then project configuration, then default.
	pick := func(flagSet bool, flagVal, cfgVal, def string) string {
		switch {
		case flagSet && flagVal != "":
			return flagVal
		case cfgVal != "":
			return cfgVal
		default:
			return def
		}
	}

	cfgStr := func(get func(*config.File) string) string {
		if cfg == nil {
			return ""
		}
		return get(cfg)
	}

	selected := pick(set["agent"], *agentName, cfgStr(func(c *config.File) string { return c.Agent }), "shell")
	selectedImage := pick(set["image"], *image, cfgStr(func(c *config.File) string { return c.Image }), "")
	selectedWorkdir := pick(set["workdir"], *workdir, cfgStr(func(c *config.File) string { return c.Workdir }), "")
	selectedWorkspace := pick(set["workspace"], *workspace, cfgStr(func(c *config.File) string { return c.Workspace }), "")
	selectedHostname := pick(set["hostname"], *hostname, cfgStr(func(c *config.File) string { return c.Hostname }), "")
	readOnlyWorkspace := *roWorkspace
	if !set["read-only-workspace"] && cfg != nil {
		readOnlyWorkspace = cfg.ReadOnlyWorkspace
	}
	selectedNetwork := pick(set["network"], *network, cfgStr(func(c *config.File) string { return c.Network }), "")
	selectedMemory := pick(set["memory"], *memory, cfgStr(func(c *config.File) string { return c.Memory }), "")
	selectedCPUs := pick(set["cpus"], *cpus, cfgStr(func(c *config.File) string { return c.CPUs }), "")

	selectedPids := *pidsLimit
	if selectedPids == 0 && cfg != nil {
		selectedPids = cfg.PidsLimit
	}

	noConfig := *noUserConfig
	if !set["no-user-config"] && cfg != nil && cfg.UserConfig != nil && !*cfg.UserConfig {
		noConfig = true
	}

	if len(command) == 0 && cfg != nil {
		command = cfg.Command
	}
	envNames := append([]string{}, envs...)
	extraMounts := append([]string{}, mounts...)
	if cfg != nil {
		envNames = append(envNames, cfg.Env...)
		extraMounts = append(extraMounts, cfg.Mounts...)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: locating home directory: %v\n", err)
		return 1
	}
	reg := agent.New(home)

	def, err := reg.Get(selected)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 2
	}

	var installed update.Record
	var installedOK bool
	if selectedImage == "" {
		state, err := update.LoadState()
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 1
		}
		installed, installedOK = state.For(selected)
		if installedOK {
			selectedImage = installed.Image
		}
	}
	if noConfig {
		if def, err = reg.WithoutUserConfig(selected); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 2
		}
	}
	if *forceShell {
		def.Command = []string{"/bin/bash", "-l"}
	}

	req := policy.Request{
		AgentName:         selected,
		NoUserConfig:      noConfig,
		UserAuth:          *userAuth,
		WorkdirOverride:   selectedWorkdir,
		WorkspaceOverride: selectedWorkspace,
		ReadOnlyWorkspace: readOnlyWorkspace,
		ExtraMounts:       extraMounts,
		EnvNames:          envNames,
		NetworkMode:       selectedNetwork,
		Memory:            selectedMemory,
		CPUs:              selectedCPUs,
		PidsLimit:         selectedPids,
		Command:           command,
		Image:             selectedImage,
		ImageVersion:      installed.Version,
		Hostname:          selectedHostname,
	}

	resolver := policy.NewResolver(fsx.Real{}, os.LookupEnv)
	resolver.Strict = *strictConfig

	var logger *audit.Logger
	if *auditLog != "" {
		f, err := os.OpenFile(*auditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: opening audit log: %v\n", err)
			return 1
		}
		defer f.Close()
		logger = audit.New(f)
	}

	opts := session.Options{
		Resolver:  resolver,
		Audit:     logger,
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		TTY:       isTerminal(os.Stdin) && isTerminal(os.Stdout),
		PrintArgv: *printArgv,
	}

	code, err := runSession(opts, def, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func usage(fs *flag.FlagSet) {
	fmt.Fprintf(fs.Output(), `agentbox — run a coding agent inside a contained sandbox

Usage:
  agentbox [flags] [--] [command...]
  agentbox create [flags] NAME
  agentbox list [--json]
  agentbox open [flags] NAME [-- command...]
  agentbox inspect [--json] NAME
  agentbox remove [--force] NAME
  agentbox refresh [--strict-config] NAME
  agentbox exec <name> -- <command...>
  agentbox images build [agent...]
  agentbox images check [--agent NAME]
  agentbox images update [--agent NAME] [--dry-run]
  agentbox images rollback <agent> <version>
  agentbox doctor
  agentbox version

The default invocation is the command: trailing arguments run inside the
container. Reserved words (create, list, open, inspect, remove, refresh, exec,
images, doctor, version) are recognized only in first position; use "--" to run
one of them as a program instead.

Flags:
`)
	fs.PrintDefaults()
}

func ensureImageAvailable(reqImage string, def agent.Definition, noUserConfig bool) error {
	image := reqImage
	if image == "" {
		image = def.Image
	}
	// Only auto-build if it's a default (localhost/agentbox/...) image.
	// Custom images must exist; let podman fail with a clear error if not.
	if !strings.HasPrefix(image, agent.ImageRepository+"/") {
		return nil
	}
	// Check if image exists locally.
	if imageExists(image) {
		return nil
	}
	// Determine targets to build. Need base if target isn't base.
	raw := strings.TrimPrefix(image, agent.ImageRepository+"/")
	target, requestedVersion, hasVersion := strings.Cut(raw, ":")
	var targets []string
	if target == "base" || target == "shell" {
		targets = []string{"base"}
	} else {
		targets = []string{"base", target}
	}

	pins, err := loadPins()
	if err != nil {
		return err
	}
	versions := map[string]string{}
	if hasVersion && requestedVersion != "latest" && target != "base" && target != "shell" {
		if err := policy.ValidateAgentVersion(requestedVersion); err != nil {
			return err
		}
		state, err := update.LoadState()
		if err != nil {
			return err
		}
		rec, ok := state.For(target)
		if !ok || rec.Version != requestedVersion {
			rec, ok = state.Historical(target, requestedVersion)
		}
		if !ok {
			return fmt.Errorf("image %s is missing and has no recorded build inputs", image)
		}
		pins = pins.WithAgent(target, update.AgentPin{Version: rec.Version, Args: rec.Args, Source: rec.Source})
		versions[target] = requestedVersion
	}
	return buildTargetsWithPins(targets, pins, versions)
}

func imageExists(ref string) bool {
	cmd := execCommand("podman", "image", "exists", ref)
	return cmd.Run() == nil
}

// sortedMountSummary is used by tests and diagnostics.
func sortedMountSummary(ms []policy.ResolvedMount) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Host+":"+m.Dest+":"+m.Access.String())
	}
	sort.Strings(out)
	return out
}
