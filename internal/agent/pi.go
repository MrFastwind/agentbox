package agent

import "path/filepath"

// pi breaks the config/state split. One directory — ~/.pi/agent/ — holds
// auth.json, settings.json, oauth.json, models.json, trust.json, sessions and
// the npm tree. PI_CODING_AGENT_DIR moves the whole directory as a unit, so
// there is no way to mount configuration without also exposing credentials.
//
// Therefore pi uses StrategySeed with an ALLOW-LIST, and the allow-list is the
// security boundary. What it deliberately does not name:
//
//	auth.json              api_key / oauth credentials
//	oauth.json             live access + refresh tokens
//	oauth.json.migrated    the same, left behind by migration
//	trust.json             pre-trusts workspace paths, which decides whether a
//	                       repository may control the agent's own prompt and
//	                       package list
//	npm/, bin/, sessions/  executable and state trees
//	pi-debug.log           agent-written, may echo the environment
//
// settings.json and models.json ARE seeded, but only through StripCredentialKeys:
// pi's own migration reads settings.apiKeys, and models.json carries
// providers.<id>.apiKey. Stripping them is what makes seeding defensible.
//
// models-store.json is seeded as-is: it was verified to hold no credential
// material. It is only medium-trust because pi builds it with the same backend
// as auth.json, so it stays behind the content assertion.
func piDef(home string) Definition {
	const (
		agentDirInContainer = configHome + "/pi"
		sessionsInContainer = stateHome + "/pi/sessions"
	)
	base := baseEnv()
	base["PI_CODING_AGENT_DIR"] = agentDirInContainer
	base["PI_CODING_AGENT_SESSION_DIR"] = sessionsInContainer
	return Definition{
		Name:                 "pi",
		Image:                DefaultImage("pi"),
		Command:              []string{"pi"},
		Strategy:             StrategySeed,
		ConfigDir:            filepath.Join(home, ".pi", "agent"),
		ConfigDirInContainer: agentDirInContainer,

		SeedFiles: []SeedSpec{
			{Rel: "settings.json", Transform: StripCredentialKeys{}},
			{Rel: "models.json", Transform: StripCredentialKeys{}},
			{Rel: "models-store.json", Transform: Identity{}},
		},

		BaseEnv:        base,
		PassthroughEnv: []string{"TERM", "LANG", "LC_ALL", "COLORTERM"},

		// Provider keys pi understands. Absent the flag, none of these cross.
		EnvAllowlist: []string{
			"PI_CODING_AGENT_DIR",
			"ANTHROPIC_API_KEY",
			"OPENAI_API_KEY",
			"OPENCODE_API_KEY",
			"GEMINI_API_KEY",
			"OPENROUTER_API_KEY",
			"GROQ_API_KEY",
			"MISTRAL_API_KEY",
			"XAI_API_KEY",
		},

		StateDirs: []string{
			homeDir,
			configHome,
			agentDirInContainer,
			dataHome,
			stateHome,
			stateHome + "/pi",
			sessionsInContainer,
			cacheHome,
		},
	}
}
