package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"agentbox/internal/agent"
	"agentbox/internal/audit"
	"agentbox/internal/config"
	"agentbox/internal/fsx"
	"agentbox/internal/instance"
	"agentbox/internal/policy"
	"agentbox/internal/session"
)

// runCreate stores a named profile. It does not start a sandbox: creating an
// instance is cheap and must not require podman or a built image.
func runCreate(args []string) int {
	fs := flag.NewFlagSet("agentbox create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: agentbox create [flags] NAME")
		fs.PrintDefaults()
	}

	var (
		agentName    = fs.String("agent", "", "agent to store (opencode, pi, claude, antigravity, shell)")
		image        = fs.String("image", "", "override the sandbox image")
		configPath   = fs.String("config", "", "project configuration to seed the instance (never auto-discovered)")
		noUserConfig = fs.Bool("no-user-config", false, "clone no host agent configuration")
		network      = fs.String("network", "", "network mode: pasta, none, private, host")
		memory       = fs.String("memory", "", "memory limit")
		cpus         = fs.String("cpus", "", "CPU limit")
		pidsLimit    = fs.Int("pids-limit", 0, "process count limit")
		hostname     = fs.String("hostname", "", "container hostname")
		workdir      = fs.String("workdir", "", "default working directory")
		roWorkspace  = fs.Bool("read-only-workspace", false, "mount the workspace read-only on open")
		strictConfig = fs.Bool("strict-config", false, "refuse host configuration with credential-shaped keys")
		persistState = fs.Bool("persist-state", true, "keep a persistent HOME for this instance")
	)
	var envs, mounts stringSlice
	fs.Var(&envs, "env", "environment name to allow on open (repeatable)")
	fs.Var(&mounts, "mount", "extra mount SRC:DST[:ro|rw] to store (repeatable)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fs.Usage()
		return 2
	}
	name := rest[0]
	if err := policy.ValidateInstanceName(name); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 2
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
	selectedHostname := pick(set["hostname"], *hostname, cfgStr(func(c *config.File) string { return c.Hostname }), "")
	selectedWorkdir := pick(set["workdir"], *workdir, cfgStr(func(c *config.File) string { return c.Workdir }), "")
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
	readOnlyWorkspace := *roWorkspace
	if !set["read-only-workspace"] && cfg != nil {
		readOnlyWorkspace = cfg.ReadOnlyWorkspace
	}
	envNames := append([]string{}, envs...)
	extraMounts := append([]string{}, mounts...)
	var command []string
	if cfg != nil {
		envNames = append(envNames, cfg.Env...)
		extraMounts = append(extraMounts, cfg.Mounts...)
		command = cfg.Command
	}
	envNames = uniqueStrings(envNames)
	extraMounts = uniqueStrings(extraMounts)

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

	userConfig := !noConfig
	stored := config.File{
		Agent:             selected,
		Image:             selectedImage,
		Hostname:          selectedHostname,
		Workdir:           selectedWorkdir,
		Network:           selectedNetwork,
		Memory:            selectedMemory,
		CPUs:              selectedCPUs,
		PidsLimit:         selectedPids,
		Env:               envNames,
		Mounts:            extraMounts,
		Command:           command,
		ReadOnlyWorkspace: readOnlyWorkspace,
		UserConfig:        &userConfig,
	}

	store, err := instance.OpenStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	inst, err := store.Create(name, stored, *persistState)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}

	if !noConfig && def.Strategy != agent.StrategyNone {
		resolver := policy.NewResolver(fsx.Real{}, os.LookupEnv)
		resolver.Strict = *strictConfig
		warnings, err := store.CloneConfig(inst, def, resolver, *strictConfig)
		for _, warning := range warnings {
			fmt.Fprintf(os.Stderr, "agentbox: %s\n", warning)
		}
		if err != nil {
			_ = store.Remove(name)
			fmt.Fprintf(os.Stderr, "agentbox: cloning configuration: %v\n", err)
			return 1
		}
	}

	fmt.Printf("created instance %s (%s)\n", name, def.Name)
	return 0
}

// runOpen starts a fresh sandbox for a saved instance. The instance supplies
// the profile; the current directory supplies the workspace.
func runOpen(args []string) int {
	fs := flag.NewFlagSet("agentbox open", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: agentbox open [flags] NAME [-- command...]")
		fs.PrintDefaults()
	}
	var (
		workspace    = fs.String("workspace", "", "mount this subdirectory as the workspace instead of the launch directory")
		roWorkspace  = fs.Bool("read-only-workspace", false, "mount the workspace read-only")
		noUserConfig = fs.Bool("no-user-config", false, "read no stored agent configuration")
		network      = fs.String("network", "", "override network mode")
		memory       = fs.String("memory", "", "override memory limit")
		cpus         = fs.String("cpus", "", "override CPU limit")
		pidsLimit    = fs.Int("pids-limit", 0, "override process count limit")
		workdir      = fs.String("workdir", "", "override the launch directory")
		strictConfig = fs.Bool("strict-config", false, "refuse stored configuration with credential-shaped keys")
		auditLog     = fs.String("audit-log", "", "append a JSON decision record to this file")
		printArgv    = fs.Bool("print-argv", false, "print the podman argv and exit")
		replace      = fs.Bool("replace", false, "remove an existing container with this instance name")
	)
	var envs, mounts stringSlice
	fs.Var(&envs, "env", "pass one host environment variable (repeatable; allow-listed per agent)")
	fs.Var(&mounts, "mount", "extra mount SRC:DST[:ro|rw] (repeatable; deny-list validated)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}
	name := rest[0]
	rest = rest[1:]
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	} else if len(rest) > 0 {
		fmt.Fprintln(os.Stderr, "agentbox: open: command arguments must follow --")
		return 2
	}

	store, err := instance.OpenStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	inst, err := store.Load(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	selected := inst.Config.Agent
	if selected == "" {
		selected = "shell"
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

	noConfig := inst.Config.UserConfig != nil && !*inst.Config.UserConfig
	if set["no-user-config"] {
		noConfig = *noUserConfig
	}
	if noConfig {
		if def, err = reg.WithoutUserConfig(selected); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 2
		}
	}

	selectedWorkdir := inst.Config.Workdir
	if set["workdir"] {
		selectedWorkdir = *workdir
	}
	selectedWorkspace := ""
	if set["workspace"] {
		selectedWorkspace = *workspace
	}
	readOnlyWorkspace := inst.Config.ReadOnlyWorkspace
	if set["read-only-workspace"] {
		readOnlyWorkspace = *roWorkspace
	}
	selectedNetwork := inst.Config.Network
	if set["network"] {
		selectedNetwork = *network
	}
	selectedMemory := inst.Config.Memory
	if set["memory"] {
		selectedMemory = *memory
	}
	selectedCPUs := inst.Config.CPUs
	if set["cpus"] {
		selectedCPUs = *cpus
	}
	selectedPids := inst.Config.PidsLimit
	if set["pids-limit"] {
		selectedPids = *pidsLimit
	}
	envNames := append([]string{}, inst.Config.Env...)
	envNames = append(envNames, envs...)
	envNames = uniqueStrings(envNames)
	extraMounts := append([]string{}, inst.Config.Mounts...)
	extraMounts = append(extraMounts, mounts...)
	extraMounts = uniqueStrings(extraMounts)

	command := inst.Config.Command
	if len(rest) > 0 {
		command = rest
	}

	containerName := inst.ContainerName()
	if status, exists := podmanContainerStatus(containerName); exists {
		if !*replace {
			fmt.Fprintf(os.Stderr, "agentbox: container %s already exists (%s); use --replace to remove it\n", containerName, status)
			return 1
		}
		if err := podmanRemove(containerName); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: removing container: %v\n", err)
			return 1
		}
	}

	configRoot := ""
	if !noConfig {
		configRoot = inst.ConfigRoot()
	}
	instanceHome := ""
	if inst.Meta.PersistState {
		instanceHome = inst.Home()
	}
	req := policy.Request{
		AgentName:         selected,
		NoUserConfig:      noConfig,
		InstanceName:      name,
		InstanceRoot:      store.Root,
		InstanceHome:      instanceHome,
		ConfigRoot:        configRoot,
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
		Image:             inst.Config.Image,
		Hostname:          inst.Config.Hostname,
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
		Name:      containerName,
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

type listRecord struct {
	Name         string `json:"name"`
	Container    string `json:"container"`
	Status       string `json:"status,omitempty"`
	Agent        string `json:"agent"`
	Image        string `json:"image,omitempty"`
	PersistState bool   `json:"persist_state"`
	Error        string `json:"error,omitempty"`
}

func runList(args []string) int {
	fs := flag.NewFlagSet("agentbox list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: agentbox list [--json]")
		fs.PrintDefaults()
	}
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	store, err := instance.OpenStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	entries, err := store.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	records := make([]listRecord, 0, len(entries))
	for _, entry := range entries {
		rec := listRecord{Name: entry.Name, Container: "agentbox-" + entry.Name}
		if entry.Err != nil {
			rec.Error = entry.Err.Error()
		} else {
			rec.Agent = entry.Instance.Config.Agent
			rec.Image = entry.Instance.Config.Image
			rec.PersistState = entry.Instance.Meta.PersistState
			if status, ok := podmanContainerStatus(rec.Container); ok {
				rec.Status = status
			}
		}
		records = append(records, rec)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(records); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 1
		}
		return 0
	}
	if len(records) == 0 {
		fmt.Println("no instances")
		return 0
	}
	fmt.Printf("%-24s %-12s %-12s %s\n", "NAME", "STATUS", "AGENT", "HOME")
	for _, rec := range records {
		status := rec.Status
		if status == "" {
			status = "-"
		}
		if rec.Error != "" {
			status = "invalid"
		}
		home := "ephemeral"
		if rec.PersistState {
			home = "persistent"
		}
		if rec.Error != "" {
			fmt.Printf("%-24s %-12s %-12s %s\n", rec.Name, status, "-", rec.Error)
			continue
		}
		fmt.Printf("%-24s %-12s %-12s %s\n", rec.Name, status, rec.Agent, home)
	}
	return 0
}

type inspectRecord struct {
	Name         string                   `json:"name"`
	Dir          string                   `json:"dir"`
	Container    string                   `json:"container"`
	Status       string                   `json:"status,omitempty"`
	Agent        string                   `json:"agent"`
	Image        string                   `json:"image,omitempty"`
	Hostname     string                   `json:"hostname,omitempty"`
	Workdir      string                   `json:"workdir,omitempty"`
	Network      string                   `json:"network,omitempty"`
	Memory       string                   `json:"memory,omitempty"`
	CPUs         string                   `json:"cpus,omitempty"`
	PidsLimit    int                      `json:"pids_limit,omitempty"`
	ReadOnly     bool                     `json:"read_only_workspace"`
	PersistState bool                     `json:"persist_state"`
	ConfigSource string                   `json:"config_source"`
	EnvNames     []string                 `json:"env_names,omitempty"`
	Mounts       []string                 `json:"mounts,omitempty"`
	Command      []string                 `json:"command,omitempty"`
	Created      string                   `json:"created,omitempty"`
	ClonedAt     string                   `json:"cloned_at,omitempty"`
	ClonedFrom   string                   `json:"cloned_from,omitempty"`
	Files        []instance.ManifestEntry `json:"cloned_files,omitempty"`
}

func runInspect(args []string) int {
	fs := flag.NewFlagSet("agentbox inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: agentbox inspect [--json] NAME")
		fs.PrintDefaults()
	}
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	name := fs.Arg(0)
	store, err := instance.OpenStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	inst, err := store.Load(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	rec := inspectRecord{
		Name:         inst.Name,
		Dir:          inst.Dir,
		Container:    inst.ContainerName(),
		Agent:        inst.Config.Agent,
		Image:        inst.Config.Image,
		Hostname:     inst.Config.Hostname,
		Workdir:      inst.Config.Workdir,
		Network:      inst.Config.Network,
		Memory:       inst.Config.Memory,
		CPUs:         inst.Config.CPUs,
		PidsLimit:    inst.Config.PidsLimit,
		ReadOnly:     inst.Config.ReadOnlyWorkspace,
		PersistState: inst.Meta.PersistState,
		ConfigSource: "instance",
		EnvNames:     inst.Config.Env,
		Mounts:       inst.Config.Mounts,
		Command:      inst.Config.Command,
		Created:      formatTime(inst.Meta.Created),
		ClonedAt:     formatTime(inst.Meta.Source.ClonedAt),
		ClonedFrom:   inst.Meta.Source.ConfigDir,
		Files:        inst.Meta.Source.Files,
	}
	if rec.Agent == "" {
		rec.Agent = "shell"
	}
	if rec.Hostname == "" {
		rec.Hostname = policy.DefaultInstanceHostname(inst.Name)
	}
	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		reg := agent.New(home)
		if def, defErr := reg.Get(rec.Agent); defErr == nil {
			if rec.Image == "" {
				rec.Image = def.Image
			}
			if def.Strategy == agent.StrategyNone {
				rec.ConfigSource = "none"
			}
		}
	}
	if inst.Config.UserConfig != nil && !*inst.Config.UserConfig {
		rec.ConfigSource = "none"
	}
	if status, ok := podmanContainerStatus(rec.Container); ok {
		rec.Status = status
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rec); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Printf("name            %s\n", rec.Name)
	fmt.Printf("directory       %s\n", rec.Dir)
	fmt.Printf("container       %s\n", rec.Container)
	fmt.Printf("status          %s\n", valueOrDash(rec.Status))
	fmt.Printf("agent           %s\n", rec.Agent)
	fmt.Printf("image           %s\n", valueOrDash(rec.Image))
	fmt.Printf("hostname        %s\n", valueOrDash(rec.Hostname))
	fmt.Printf("workdir         %s\n", valueOrDash(rec.Workdir))
	fmt.Printf("network         %s\n", valueOrDash(rec.Network))
	fmt.Printf("config source   %s\n", rec.ConfigSource)
	fmt.Printf("persistent home %t\n", rec.PersistState)
	fmt.Printf("created         %s\n", valueOrDash(rec.Created))
	if rec.ClonedFrom != "" {
		fmt.Printf("cloned from     %s at %s\n", rec.ClonedFrom, rec.ClonedAt)
		for _, file := range rec.Files {
			fmt.Printf("  %-40s %8d  %s\n", file.Rel, file.Size, file.SHA256)
		}
	}
	if len(rec.EnvNames) > 0 {
		fmt.Printf("env names       %s\n", strings.Join(rec.EnvNames, ", "))
	}
	if len(rec.Mounts) > 0 {
		fmt.Printf("mounts          %s\n", strings.Join(rec.Mounts, ", "))
	}
	return 0
}

func runRemove(args []string) int {
	fs := flag.NewFlagSet("agentbox remove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: agentbox remove [--force] NAME")
		fs.PrintDefaults()
	}
	force := fs.Bool("force", false, "remove even if the container is running")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	name := fs.Arg(0)
	if err := policy.ValidateInstanceName(name); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 2
	}
	store, err := instance.OpenStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	container := "agentbox-" + name
	status, exists := podmanContainerStatus(container)
	if exists {
		if status == "running" && !*force {
			fmt.Fprintf(os.Stderr, "agentbox: instance %s is running; use --force to remove it\n", name)
			return 1
		}
		if err := podmanRemove(container); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: removing container: %v\n", err)
			return 1
		}
	}
	if _, err := store.Load(name); err != nil && !*force {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	if err := store.Remove(name); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	fmt.Printf("removed instance %s\n", name)
	return 0
}

func runRefresh(args []string) int {
	fs := flag.NewFlagSet("agentbox refresh", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: agentbox refresh [--strict-config] NAME")
		fs.PrintDefaults()
	}
	strictConfig := fs.Bool("strict-config", false, "refuse host configuration with credential-shaped keys")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	name := fs.Arg(0)
	store, err := instance.OpenStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	inst, err := store.Load(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	if status, ok := podmanContainerStatus(inst.ContainerName()); ok && status == "running" {
		fmt.Fprintf(os.Stderr, "agentbox: instance %s is running; stop it before refreshing\n", name)
		return 1
	}
	if inst.Config.UserConfig != nil && !*inst.Config.UserConfig {
		fmt.Fprintf(os.Stderr, "agentbox: instance %s was created without host configuration\n", name)
		return 1
	}
	selected := inst.Config.Agent
	if selected == "" {
		selected = "shell"
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
	if def.Strategy == agent.StrategyNone {
		fmt.Printf("instance %s uses an agent with no host configuration\n", name)
		return 0
	}
	resolver := policy.NewResolver(fsx.Real{}, os.LookupEnv)
	resolver.Strict = *strictConfig
	warnings, err := store.CloneConfig(inst, def, resolver, *strictConfig)
	for _, warning := range warnings {
		fmt.Fprintf(os.Stderr, "agentbox: %s\n", warning)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: refreshing configuration: %v\n", err)
		return 1
	}
	fmt.Printf("refreshed instance %s\n", name)
	return 0
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
