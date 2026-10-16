package agent

// shellDef is the bare sandbox: no agent, no host configuration, just a shell
// in the base image. It is a first-class definition rather than a special case
// in the command layer, so "--no-user-config" with no agent selected takes the
// same path as everything else.
func shellDef() Definition {
	return Definition{
		Name:                 "shell",
		Image:                DefaultImage("base"),
		Command:              []string{"/bin/bash", "-l"},
		Strategy:             StrategyNone,
		ConfigDirInContainer: configHome + "/shell",
		BaseEnv:              baseEnv(),
		PassthroughEnv:       []string{"TERM", "LANG", "LC_ALL", "COLORTERM"},
		EnvAllowlist:         nil,
		StateDirs: []string{
			homeDir,
			configHome,
			configHome + "/shell",
			dataHome,
			stateHome,
			cacheHome,
		},
	}
}
