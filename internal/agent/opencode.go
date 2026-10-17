package agent

import "path/filepath"

// opencode config and state are cleanly split on the host:
//
//	~/.config/opencode/       static configuration      -> mounted :ro
//	~/.local/share/opencode/  state, db, auth.json 0600  -> NEVER mounted
//
// The state directory is the one that holds secrets, and it is protected by a
// directory-level rule: it is simply never read. That is stronger than a file
// deny-list, and it is why opencode uses StrategyMount while pi cannot.
func opencodeDef(home string) Definition {
	const configInContainer = configHome + "/opencode"
	base := baseEnv()
	base["OPENCODE_CONFIG_DIR"] = configInContainer
	return Definition{
		Name:                 "opencode",
		Image:                DefaultImage("opencode"),
		Command:              []string{"opencode"},
		Strategy:             StrategyMount,
		ConfigDir:            filepath.Join(home, ".config", "opencode"),
		ConfigDirInContainer: configInContainer,

		// ~/.config/opencode/skills is a symlink out of the config directory,
		// typically onto another volume — the home directory itself reaches
		// out through ~/media, so the link can resolve outside realpath(home)
		// while being written entirely inside it. The bound accepts either
		// form, and the resolved target must then clear the deny-list, which
		// is what still refuses a link into ~/.ssh. A link failing either
		// check is skipped with a warning, never silently mounted.
		SymlinkTargetPrefixes: []string{home},

		// Even though the directory is mounted, these names never cross. This
		// is the ~/.config/**/auth.json rule: cli.json and service.json live
		// here too, so "static config only" is not a safe assumption.
		DeniedNames: []string{
			"auth.json",
			"account.json",
			"oauth.json",
			"oauth.json.migrated",
			"trust.json",
			"credentials",
			"credentials.json",
			"credentials*.json",
			"*.pem",
			"*.key",
			"id_rsa",
			"id_ed25519",
		},

		BaseEnv:        base,
		PassthroughEnv: []string{"TERM", "LANG", "LC_ALL", "COLORTERM"},

		// Only these may cross, and only when --env names them explicitly.
		EnvAllowlist: []string{"OPENCODE_API_KEY", "OPENCODE_CONFIG"},

		StateDirs: []string{
			homeDir,
			configHome,
			configHome + "/opencode",
			dataHome,
			stateHome,
			cacheHome,
		},
	}
}
