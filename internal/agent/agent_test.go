package agent_test

import (
	"strings"
	"testing"

	"agentbox/internal/agent"
)

func TestRegistryKnowsItsAgents(t *testing.T) {
	reg := agent.New("/home/u")
	for _, want := range []string{"opencode", "pi", "claude", "antigravity", "shell"} {
		if _, err := reg.Get(want); err != nil {
			t.Errorf("expected agent %q: %v", want, err)
		}
	}
	if _, err := reg.Get("nope"); err == nil {
		t.Error("expected an error for an unknown agent")
	}
}

func TestPiNeverSeedsCredentialFiles(t *testing.T) {
	reg := agent.New("/home/u")
	def, err := reg.Get("pi")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range def.SeedFiles {
		for _, forbidden := range []string{"auth.json", "oauth.json", "oauth.json.migrated", "trust.json"} {
			if s.Rel == forbidden {
				t.Fatalf("%s is on the seed allow-list", forbidden)
			}
		}
	}
}

func TestClaudeNeverSeedsCredentialFiles(t *testing.T) {
	reg := agent.New("/home/u")
	def, err := reg.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		".credentials.json",
		".claude.json",
		"history.jsonl",
		"projects",
		"plugins",
	}
	for _, s := range def.SeedFiles {
		for _, bad := range forbidden {
			if s.Rel == bad {
				t.Fatalf("%s is on the claude seed allow-list", bad)
			}
		}
	}
}

func TestAntigravityNeverSeedsCredentialFiles(t *testing.T) {
	reg := agent.New("/home/u")
	def, err := reg.Get("antigravity")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"antigravity-cli/antigravity-oauth-token",
		"google_accounts.json",
		"oauth_creds.json",
		"trustedFolders.json",
		"installation_id",
		"state.json",
		"projects.json",
	}
	for _, s := range def.SeedFiles {
		for _, bad := range forbidden {
			if s.Rel == bad {
				t.Fatalf("%s is on the antigravity seed allow-list", bad)
			}
		}
	}
}

// Every registered agent must name a fully-qualified image, so podman never
// resolves an unprefixed name through an untrusted search list.
func TestRegistryImagesAreFullyQualified(t *testing.T) {
	reg := agent.New("/home/u")
	for _, name := range []string{"opencode", "pi", "claude", "antigravity", "shell"} {
		def, err := reg.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(def.Image, "localhost/agentbox/") && !strings.Contains(def.Image, ".") {
			t.Errorf("%s image %q is not fully qualified", name, def.Image)
		}
	}
}

func TestConfigDirEnvVar(t *testing.T) {
	reg := agent.New("/home/u")
	for _, tc := range []struct {
		agent string
		want  string
	}{
		{"opencode", "OPENCODE_CONFIG_DIR"},
		{"pi", "PI_CODING_AGENT_DIR"},
		{"claude", "CLAUDE_CONFIG_DIR"},
		// antigravity has no config-dir variable; the entrypoint is told
		// the seed destination explicitly instead.
		{"antigravity", ""},
		{"shell", ""},
	} {
		def, err := reg.Get(tc.agent)
		if err != nil {
			t.Fatal(err)
		}
		if got := def.ConfigDirEnvVar(); got != tc.want {
			t.Errorf("%s: ConfigDirEnvVar = %q, want %q", tc.agent, got, tc.want)
		}
	}
}

func TestWithoutUserConfigRemovesHostFacts(t *testing.T) {
	reg := agent.New("/home/u")
	def, err := reg.WithoutUserConfig("pi")
	if err != nil {
		t.Fatal(err)
	}
	if def.Strategy != agent.StrategyNone {
		t.Errorf("expected StrategyNone, got %v", def.Strategy)
	}
	if def.ConfigDir != "" || len(def.SeedFiles) != 0 {
		t.Error("host configuration facts survived WithoutUserConfig")
	}
}

func TestCredentialKeyPathsFindsNestedAndCaseVariant(t *testing.T) {
	raw := []byte(`{
		"theme": "dark",
		"apiKeys": {"anthropic": "sk-a"},
		"providers": {"openai": {"API_KEY": "sk-b", "model": "gpt"}},
		"tokens": [{"access_token": "x"}]
	}`)
	paths, err := agent.CredentialKeyPaths(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"apiKeys", "providers.openai.API_KEY", "tokens[0].access_token"} {
		found := false
		for _, p := range paths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %q among %v", want, paths)
		}
	}
}

func TestStripRemovesOnlyCredentialKeys(t *testing.T) {
	raw := []byte(`{"theme":"dark","apiKeys":{"a":"sk"},"nested":{"secret":"s","keep":1}}`)
	out, removed, err := agent.StripCredentialKeysFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Fatalf("expected 2 removed keys, got %v", removed)
	}
	s := string(out)
	for _, gone := range []string{"sk\"", "apiKeys", "secret"} {
		if strings.Contains(s, gone) {
			t.Errorf("credential material %q survived stripping: %s", gone, s)
		}
	}
	for _, kept := range []string{"dark", "keep"} {
		if !strings.Contains(s, kept) {
			t.Errorf("non-credential value %q was lost: %s", kept, s)
		}
	}
}

func TestStripRemovesProviderPrefixedCredentialKeys(t *testing.T) {
	raw := []byte(`{
		"env": {
			"ANTHROPIC_API_KEY": "sk-ant",
			"ANTHROPIC_AUTH_TOKEN": "tok",
			"AWS_SECRET_ACCESS_KEY": "aws",
			"CLAUDE_CODE_USE_BEDROCK": "1",
			"MAX_TOKENS": "4096"
		}
	}`)
	out, removed, err := agent.StripCredentialKeysFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("expected 3 provider-prefixed keys removed, got %v", removed)
	}
	s := string(out)
	for _, gone := range []string{"sk-ant", "tok", "aws\""} {
		if strings.Contains(s, gone) {
			t.Errorf("credential material %q survived stripping: %s", gone, s)
		}
	}
	for _, kept := range []string{"CLAUDE_CODE_USE_BEDROCK", "MAX_TOKENS"} {
		if !strings.Contains(s, kept) {
			t.Errorf("non-credential setting %q was lost: %s", kept, s)
		}
	}
}

func TestStripLeavesNonJSONAlone(t *testing.T) {
	raw := []byte("not json at all")
	out, removed, err := agent.StripCredentialKeys{}.Apply(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(raw) || len(removed) != 0 {
		t.Fatalf("non-JSON input should pass through untouched")
	}
}
