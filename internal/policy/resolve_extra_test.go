package policy_test

import (
	"strings"
	"testing"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
	"agentbox/internal/policy"
)

// --- env: requested-but-unset ----------------------------------------------

func TestEnvRequestedButUnsetWarns(t *testing.T) {
	// ANTHROPIC_API_KEY is on pi's allowlist but absent from the host env.
	spec, err := resolve(t, piHost(), "pi", policy.Request{
		LaunchDir: testHome + "/project",
		EnvNames:  []string{"ANTHROPIC_API_KEY"},
	}, map[string]string{})
	if err != nil {
		t.Fatalf("a missing host variable must not abort the run: %v", err)
	}
	for _, e := range spec.Env {
		if e.Name == "ANTHROPIC_API_KEY" {
			t.Fatal("an unset variable must not cross")
		}
	}
	warned := false
	for _, r := range spec.Refusals {
		if r.Kind == policy.RefusalEnv && !r.Fatal && strings.Contains(r.Reason, "not set on the host") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected an auditable warning for the unset variable, got %+v", spec.Refusals)
	}
}

// --- launch dir override ----------------------------------------------------

func TestWorkdirOverrideTakesPrecedence(t *testing.T) {
	f := opencodeHost()
	f.Mkdir(testHome + "/project/sub")
	spec := mustResolve(t, f, "opencode", policy.Request{
		LaunchDir:       testHome + "/project",
		WorkdirOverride: testHome + "/project/sub",
	})
	if !hasMount(spec, func(m policy.ResolvedMount) bool {
		return m.Origin == "launch-dir" && m.Host == testHome+"/project/sub"
	}) {
		t.Fatalf("expected --workdir to be mounted, got %+v", spec.Mounts)
	}
}

// --- explicit mount error paths --------------------------------------------

func TestExplicitMountMalformedRefused(t *testing.T) {
	for _, raw := range []string{
		"/a",              // too few fields
		"/a:/b:bogus",     // bad access mode
		"/a:/b:ro:extra",  // too many fields
		"/a:relative/dst", // destination not absolute
	} {
		_, err := resolve(t, opencodeHost(), "opencode", policy.Request{
			LaunchDir:   testHome + "/project",
			ExtraMounts: []string{raw},
		}, nil)
		rerr := wantRefusal(t, err)
		if !strings.Contains(rerr.Error(), "mount") {
			t.Fatalf("%q: expected a mount refusal, got %v", raw, rerr)
		}
	}
}

func TestExplicitMountUnresolvableRefused(t *testing.T) {
	// A host path that does not exist cannot be resolved and must be refused.
	_, err := resolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir:   testHome + "/project",
		ExtraMounts: []string{testHome + "/project/nope:/data:ro"},
	}, nil)
	wantRefusal(t, err)
}

// --- command selection ------------------------------------------------------

func TestCommandFallsBackToLoginShell(t *testing.T) {
	f := opencodeHost()
	def := agent.Definition{
		Name:                 "custom",
		Image:                "localhost/agentbox/base:latest",
		Strategy:             agent.StrategyNone,
		ConfigDirInContainer: "/home/agent/.config/custom",
		BaseEnv:              map[string]string{"HOME": "/home/agent", "PATH": "/usr/bin"},
		StateDirs:            []string{"/home/agent"},
	}
	spec, err := policy.NewResolver(f, envFunc(nil)).Resolve(def, policy.Request{LaunchDir: testHome + "/project"})
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if strings.Join(spec.Command, " ") != "/bin/bash -l" {
		t.Fatalf("expected the login-shell fallback, got %v", spec.Command)
	}
}

func TestCommandOverrideIsPassedThrough(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir: testHome + "/project",
		Command:   []string{"npm", "test"},
	})
	if strings.Join(spec.Command, " ") != "npm test" {
		t.Fatalf("pass-through command was altered: %v", spec.Command)
	}
}

// --- image override ---------------------------------------------------------

func TestResolveImageOverride(t *testing.T) {
	// A fully-qualified override is accepted...
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir: testHome + "/project",
		Image:     "docker.io/library/debian:stable-slim",
	})
	if spec.Image != "docker.io/library/debian:stable-slim" {
		t.Fatalf("image override not applied: %s", spec.Image)
	}

	// ...an unqualified one is refused by policy, not silently resolved by podman.
	_, err := resolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir: testHome + "/project",
		Image:     "debian",
	}, nil)
	wantRefusal(t, err)
}

// --- agent config: dangling symlink ----------------------------------------

func TestAgentConfigDanglingSymlinkWarns(t *testing.T) {
	f := opencodeHost()
	// A symlink whose target does not exist.
	f.Paths[testHome+"/.config/opencode/broken"] = fsx.FakeEntry{Symlink: testHome + "/.config/opencode/does-not-exist"}

	spec := mustResolve(t, f, "opencode", policy.Request{LaunchDir: testHome + "/project"})
	for _, m := range spec.Mounts {
		if strings.HasSuffix(m.Dest, "/broken") {
			t.Fatalf("a dangling symlink must not be mounted: %+v", m)
		}
	}
	warned := false
	for _, r := range spec.Refusals {
		if r.Kind == policy.RefusalSymlink && !r.Fatal {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected a warning about the dangling symlink, got %+v", spec.Refusals)
	}
}
