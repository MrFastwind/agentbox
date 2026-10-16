// Package config loads an explicit project configuration file.
//
// There is deliberately no discovery: the file is read only when the user names
// it with --config. A configuration file found automatically in the working
// directory is not configuration, it is remote policy — a cloned repository
// could otherwise choose the agent, the network mode, the mounts and the
// credentials for a run the user believes they are controlling.
//
// Every value loaded here is an *input* to internal/policy, never a decision.
// The file may ask for host networking; policy may still refuse it.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// File is the on-disk schema. Unknown keys are an error rather than being
// ignored, so a typo cannot silently drop a security-relevant setting.
type File struct {
	Agent     string   `yaml:"agent"`
	Image     string   `yaml:"image"`
	Workdir   string   `yaml:"workdir"`
	Network   string   `yaml:"network"`
	Memory    string   `yaml:"memory"`
	CPUs      string   `yaml:"cpus"`
	PidsLimit int      `yaml:"pids_limit"`
	Env       []string `yaml:"env"`
	Mounts    []string `yaml:"mounts"`
	Command   []string `yaml:"command"`

	// Workspace mounts a subdirectory as the workspace; ReadOnlyWorkspace makes
	// that workspace read-only.
	Workspace         string `yaml:"workspace"`
	ReadOnlyWorkspace bool   `yaml:"read_only_workspace"`

	// UserConfig is a pointer so that "unset" is distinguishable from "false".
	UserConfig *bool `yaml:"user_config"`
}

func Load(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var out File
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &out, nil
}
