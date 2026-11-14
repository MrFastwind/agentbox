package agent

import "path/filepath"

// antigravity (binary "agy") keeps its settings under
// ~/.gemini/antigravity-cli/, in the same ~/.gemini tree as its credentials:
// the OAuth token (antigravity-oauth-token), the Google account cache and the
// trusted-folders list. The tree cannot be mounted, so antigravity uses
// StrategySeed.
//
// The allow-list names two pure-configuration JSON files. What it deliberately
// does not name:
//
//	antigravity-cli/antigravity-oauth-token  live OAuth token
//	google_accounts.json                     active Google account identity
//	oauth_creds.json                         Google OAuth cache
//	trustedFolders.json                      pre-trusted workspaces
//	installation_id, state.json, projects.json, history/
//
// settings.json is seeded through StripCredentialKeys because it may carry
// inline provider keys. keybindings.json is UI-only and seeded as-is.
//
// There is no documented environment variable that relocates the tree, so the
// seed destination is passed to the entrypoint explicitly instead.
func antigravityDef(home string) Definition {
	const configInContainer = homeDir + "/.gemini"
	base := baseEnv()
	base[SeedDirEnv] = configInContainer
	return Definition{
		Name:                 "antigravity",
		Image:                DefaultImage("antigravity"),
		Command:              []string{"agy"},
		Strategy:             StrategySeed,
		ConfigDir:            filepath.Join(home, ".gemini"),
		ConfigDirInContainer: configInContainer,

		SeedFiles: []SeedSpec{
			{Rel: "antigravity-cli/settings.json", Transform: StripCredentialKeys{}},
			{Rel: "antigravity-cli/keybindings.json", Transform: Identity{}},
		},

		BaseEnv:        base,
		PassthroughEnv: []string{"TERM", "LANG", "LC_ALL", "COLORTERM"},

		// API-key mode also requires modelProvider: "gemini" in settings.json.
		EnvAllowlist: []string{
			"GEMINI_API_KEY",
			"GOOGLE_CLOUD_PROJECT",
		},

		StateDirs: []string{
			homeDir,
			configHome,
			configInContainer,
			configInContainer + "/antigravity-cli",
			dataHome,
			stateHome,
			cacheHome,
		},
	}
}
