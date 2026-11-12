package policy_test

import (
	"strings"
	"testing"

	"agentbox/internal/policy"
)

// A run without an explicit hostname is identified by the agent it runs.
func TestResolveDefaultHostname(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{LaunchDir: testHome + "/project"})
	if spec.Hostname != "agentbox-opencode" {
		t.Fatalf("default hostname = %q, want agentbox-opencode", spec.Hostname)
	}

	spec = mustResolve(t, piHost(), "pi", policy.Request{LaunchDir: testHome + "/project"})
	if spec.Hostname != "agentbox-pi" {
		t.Fatalf("default hostname = %q, want agentbox-pi", spec.Hostname)
	}
}

// An explicit --hostname is honoured verbatim.
func TestResolveHostnameOverride(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir: testHome + "/project",
		Hostname:  "build-01.example.internal",
	})
	if spec.Hostname != "build-01.example.internal" {
		t.Fatalf("hostname override not applied: %q", spec.Hostname)
	}
}

// A malformed override is refused by policy, not by podman at run time.
func TestResolveHostnameInvalidRefused(t *testing.T) {
	for _, bad := range []string{"-leading", "trailing-", "has space", "under_score", "a..b", strings.Repeat("a", 65)} {
		_, err := resolve(t, opencodeHost(), "opencode", policy.Request{
			LaunchDir: testHome + "/project",
			Hostname:  bad,
		}, nil)
		rerr := wantRefusal(t, err)
		if !strings.Contains(rerr.Error(), "hostname") {
			t.Fatalf("refusal for %q does not mention hostname: %v", bad, rerr)
		}
	}
}
