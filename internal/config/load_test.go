package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFullFile(t *testing.T) {
	p := write(t, "cfg.yaml", `
agent: pi
image: docker.io/library/debian:stable-slim
hostname: agentbox-pi
workdir: /workspace
network: none
memory: 8g
cpus: "1.5"
pids_limit: 4096
workspace: sub
read_only_workspace: true
env:
  - ANTHROPIC_API_KEY
  - TERM
mounts:
  - /host/data:/data:ro
command:
  - bash
  - -l
user_config: true
`)
	f, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Agent != "pi" || f.Image != "docker.io/library/debian:stable-slim" || f.Workdir != "/workspace" {
		t.Fatalf("scalar fields not decoded: %+v", f)
	}
	if f.Hostname != "agentbox-pi" {
		t.Fatalf("hostname not decoded: %q", f.Hostname)
	}
	if f.Network != "none" || f.Memory != "8g" || f.CPUs != "1.5" || f.PidsLimit != 4096 {
		t.Fatalf("resource fields not decoded: %+v", f)
	}
	if f.Workspace != "sub" || !f.ReadOnlyWorkspace {
		t.Fatalf("workspace fields not decoded: %+v", f)
	}
	if strings.Join(f.Env, ",") != "ANTHROPIC_API_KEY,TERM" {
		t.Fatalf("env not decoded: %v", f.Env)
	}
	if len(f.Mounts) != 1 || f.Mounts[0] != "/host/data:/data:ro" {
		t.Fatalf("mounts not decoded: %v", f.Mounts)
	}
	if strings.Join(f.Command, " ") != "bash -l" {
		t.Fatalf("command not decoded: %v", f.Command)
	}
	if f.UserConfig == nil || !*f.UserConfig {
		t.Fatalf("user_config=true not decoded as a set true: %v", f.UserConfig)
	}
}

// user_config is a pointer so that "absent" and "false" stay distinguishable:
// the former defers to the default, the latter is an explicit instruction.
func TestLoadUserConfigUnsetIsNil(t *testing.T) {
	f, err := Load(write(t, "cfg.yaml", "agent: shell\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.UserConfig != nil {
		t.Fatalf("unset user_config should be nil, got %v", *f.UserConfig)
	}

	f, err = Load(write(t, "cfg.yaml", "agent: shell\nuser_config: false\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.UserConfig == nil || *f.UserConfig {
		t.Fatalf("user_config=false should be a set false, got %v", f.UserConfig)
	}
}

func TestLoadMissingFileIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("loading a missing file must fail")
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	// A typo in a security-relevant key must not be silently ignored.
	_, err := Load(write(t, "cfg.yaml", "agent: pi\nnetwrok: host\n"))
	if err == nil {
		t.Fatal("an unknown key must be an error")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Fatalf("error should identify the parse step: %v", err)
	}
}

func TestLoadRejectsMalformedYAML(t *testing.T) {
	if _, err := Load(write(t, "cfg.yaml", "agent: [unterminated\n")); err == nil {
		t.Fatal("malformed YAML must be an error")
	}
}

func TestLoadRejectsEmptyFile(t *testing.T) {
	if _, err := Load(write(t, "cfg.yaml", "")); err == nil {
		t.Fatal("an empty configuration must be an error, not an empty config")
	}
}

// The shipped example must stay parseable: it is the documentation of the
// schema, and a stale example is worse than none.
func TestShippedExampleParses(t *testing.T) {
	matches, err := filepath.Glob("../../agentbox.yaml.example")
	if err != nil || len(matches) == 0 {
		t.Skip("example config not present")
	}
	if _, err := Load(matches[0]); err != nil {
		t.Fatalf("the shipped example no longer parses: %v", err)
	}
}
