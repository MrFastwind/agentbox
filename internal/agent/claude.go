package agent

import "path/filepath"

// claude keeps configuration and credentials in one directory: ~/.claude/.
// It holds settings.json, CLAUDE.md, project history, plugins and, on Linux,
// .credentials.json (0600). The account record and per-project trust marks live
// beside it as ~/.claude.json. None of that can be mounted read-only without
// handing the sandbox live credentials, so claude uses StrategySeed.
//
// The allow-list is the boundary. What it deliberately does not name:
//
//	.credentials.json    OAuth credentials
//	.claude.json         account details and per-project trust
//	history.jsonl        prompts and responses from earlier sessions
//	projects/, sessions/ conversation state
//	plugins/, agents/    executable extensions
//
// settings.json IS seeded, but only through StripCredentialKeys: its "env"
// block may carry provider keys and "apiKeyHelper" names a command that emits
// one. keybindings.json is seeded as-is because it is pure UI configuration.
//
// CLAUDE_CONFIG_DIR relocates the whole tree, including .claude.json, so the
// container's copy is ephemeral and the host's account state is never read.
func claudeDef(home string) Definition {
	const configInContainer = homeDir + "/.claude"
	base := baseEnv()
	base["CLAUDE_CONFIG_DIR"] = configInContainer
	base["DISABLE_AUTOUPDATER"] = "1"
	base[SeedDirEnv] = configInContainer
	return Definition{
		Name:                 "claude",
		Image:                DefaultImage("claude"),
		Command:              []string{"claude"},
		Strategy:             StrategySeed,
		ConfigDir:            filepath.Join(home, ".claude"),
		ConfigDirInContainer: configInContainer,

		SeedFiles: []SeedSpec{
			{Rel: "settings.json", Transform: StripCredentialKeys{}},
			{Rel: "keybindings.json", Transform: Identity{}},
		},

		// Read only with --user-auth. .claude.json and the project/plugin trees
		// stay out: they carry trust decisions and conversation state, not just
		// authentication.
		AuthFiles: []AuthSpec{
			{Rel: ".claude/.credentials.json", ContainerRel: configInContainer + "/.credentials.json"},
		},

		BaseEnv:        base,
		PassthroughEnv: []string{"TERM", "LANG", "LC_ALL", "COLORTERM"},

		// Only these may cross, and only when --env names them explicitly.
		EnvAllowlist: []string{
			"ANTHROPIC_API_KEY",
			"ANTHROPIC_AUTH_TOKEN",
			"ANTHROPIC_BASE_URL",
		},

		StateDirs: []string{
			homeDir,
			configHome,
			configInContainer,
			dataHome,
			stateHome,
			cacheHome,
		},
	}
}
