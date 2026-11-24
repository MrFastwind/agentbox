// Package update resolves published agent releases into reviewed build pins and
// keeps the pins applied on this machine.
//
// A normal run never consults the network for an agent version. Only the
// explicit `images update` command resolves "latest"; everything it learns is
// converted into exact versions and digests before a build starts.
package update

import (
	"bytes"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"agentbox/internal/policy"
)

// PinSet is the reviewed set of build inputs. Versions and digests live here so
// the Containerfiles consumed by a binary have no floating defaults.
type PinSet struct {
	Version int                 `yaml:"version"`
	Base    PinArgs             `yaml:"base"`
	Agents  map[string]AgentPin `yaml:"agents"`
}

// PinArgs is a group of podman --build-arg values.
type PinArgs struct {
	Args map[string]string `yaml:"args"`
}

// AgentPin is one agent's exact release and build arguments.
type AgentPin struct {
	Version    string            `yaml:"version"`
	Args       map[string]string `yaml:"args"`
	Source     string            `yaml:"source,omitempty"`
	ResolvedAt string            `yaml:"resolved_at,omitempty"`
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var sha512Pattern = regexp.MustCompile(`^[0-9a-f]{128}$`)

// ParsePins reads a pins file, rejecting unknown fields and incomplete pins.
func ParsePins(data []byte) (PinSet, error) {
	var pins PinSet
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&pins); err != nil {
		return PinSet{}, fmt.Errorf("parsing pins: %w", err)
	}
	if err := pins.Validate(); err != nil {
		return PinSet{}, err
	}
	return pins, nil
}

// LoadPins reads pins from an embedded or on-disk file system.
func LoadPins(fsys fs.FS, name string) (PinSet, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return PinSet{}, fmt.Errorf("reading %s: %w", name, err)
	}
	return ParsePins(data)
}

// Validate rejects incomplete or malformed pins before they reach a build.
func (p PinSet) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported pins version %d", p.Version)
	}
	if err := validateArgs(p.Base.Args); err != nil {
		return fmt.Errorf("base pins: %w", err)
	}
	for name, pin := range p.Agents {
		if err := policy.ValidateAgentVersion(pin.Version); err != nil {
			return fmt.Errorf("agent %s: %w", name, err)
		}
		if err := validateArgs(pin.Args); err != nil {
			return fmt.Errorf("agent %s: %w", name, err)
		}
	}
	return nil
}

func validateArgs(args map[string]string) error {
	if len(args) == 0 {
		return fmt.Errorf("no build arguments")
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := args[k]
		if v == "" {
			return fmt.Errorf("%s is empty", k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("%s contains a newline", k)
		}
		if strings.Contains(k, "SHA256") && !digestPattern.MatchString(v) {
			return fmt.Errorf("%s is not a lowercase sha256 digest", k)
		}
		if k == "PI_SHA512_HEX" && !sha512Pattern.MatchString(v) {
			return fmt.Errorf("%s is not a sha512 digest", k)
		}
	}
	return nil
}

// ArgsFor returns a copy of the build arguments for a target. A copy keeps a
// caller from mutating the reviewed set in memory.
func (p PinSet) ArgsFor(target string) map[string]string {
	src := p.Base.Args
	if target != "base" {
		pin, ok := p.Agents[target]
		if !ok {
			return nil
		}
		src = pin.Args
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// WithAgent returns the pin set with one agent replaced by candidate.
func (p PinSet) WithAgent(name string, candidate AgentPin) PinSet {
	out := p
	out.Agents = make(map[string]AgentPin, len(p.Agents)+1)
	for k, v := range p.Agents {
		out.Agents[k] = v
	}
	out.Agents[name] = candidate
	return out
}
