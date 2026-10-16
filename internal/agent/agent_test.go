package agent_test

import (
	"strings"
	"testing"

	"agentbox/internal/agent"
)

func TestRegistryKnowsItsAgents(t *testing.T) {
	reg := agent.New("/home/u")
	for _, want := range []string{"opencode", "pi", "shell"} {
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
