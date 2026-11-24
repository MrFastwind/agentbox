package update

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func validPinsYAML() string {
	return fmt.Sprintf(`version: 2
base:
  args:
    ALPINE_IMAGE: public.ecr.aws/docker/library/alpine:3.22@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
agents:
  pi:
    version: 1.5.2
    args:
      ALPINE_IMAGE: public.ecr.aws/docker/library/alpine:3.22@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      NODE_VERSION: 26.13.1
      NODE_SHA256_X64: %s
      NODE_SHA256_ARM64: %s
      PI_VERSION: 1.5.2
      PI_SHA512_HEX: %s
`, strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 128))
}

func TestParsePinsAcceptsValidPins(t *testing.T) {
	pins, err := ParsePins([]byte(validPinsYAML()))
	if err != nil {
		t.Fatal(err)
	}
	if pins.Agents["pi"].Version != "1.5.2" {
		t.Fatalf("version = %q", pins.Agents["pi"].Version)
	}
}

func TestParsePinsRejectsMalformedPins(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"unknown key", strings.Replace(validPinsYAML(), "version: 2", "version: 2\nunexpected: true", 1)},
		{"legacy version", strings.Replace(validPinsYAML(), "version: 2", "version: 1", 1)},
		{"future version", strings.Replace(validPinsYAML(), "version: 2", "version: 3", 1)},
		{"bad agent version", strings.Replace(validPinsYAML(), "pi:\n    version: 1.5.2", "pi:\n    version: latest", 1)},
		{"bad digest", strings.Replace(validPinsYAML(), strings.Repeat("b", 64), "deadbeef", 1)},
		{"empty arg", strings.Replace(validPinsYAML(), "PI_VERSION: 1.5.2", "PI_VERSION: \"\"", 1)},
		{"newline in arg", strings.Replace(validPinsYAML(), "PI_VERSION: 1.5.2", `PI_VERSION: "1.5.2\nx"`, 1)},
		{"unpinned base image", strings.Replace(validPinsYAML(), "@sha256:"+strings.Repeat("a", 64), "", 2)},
		{"missing required arg", strings.Replace(validPinsYAML(), "      NODE_SHA256_ARM64: "+strings.Repeat("c", 64)+"\n", "", 1)},
		{"no args", strings.Replace(validPinsYAML(), "  args:\n    ALPINE_IMAGE: public.ecr.aws/docker/library/alpine:3.22@sha256:"+strings.Repeat("a", 64)+"\n", "", 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePins([]byte(tc.yaml)); err == nil {
				t.Fatal("ParsePins accepted malformed pins")
			}
		})
	}
}

func TestEmbeddedPinsAreValid(t *testing.T) {
	data, err := os.ReadFile("../../image/pins.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pins, err := ParsePins(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"opencode", "pi", "claude", "antigravity"} {
		if _, ok := pins.Agents[name]; !ok {
			t.Errorf("no embedded pins for %s", name)
		}
	}
	for name, args := range map[string][]string{
		"opencode":    {"OPENCODE_SHA256_X64", "OPENCODE_SHA256_ARM64"},
		"pi":          {"NODE_SHA256_X64", "NODE_SHA256_ARM64", "PI_SHA512_HEX"},
		"claude":      {"CLAUDE_SHA256_X64", "CLAUDE_SHA256_ARM64"},
		"antigravity": {"AGY_SHA256_X64", "AGY_SHA256_ARM64"},
	} {
		for _, key := range args {
			if pins.Agents[name].Args[key] == "" {
				t.Errorf("embedded pins for %s are missing %s", name, key)
			}
		}
	}
}

func TestArgsForAndWithAgentDoNotAliasPins(t *testing.T) {
	pins, err := ParsePins([]byte(validPinsYAML()))
	if err != nil {
		t.Fatal(err)
	}
	args := pins.ArgsFor("pi")
	args["PI_VERSION"] = "9.9.9"
	if pins.Agents["pi"].Args["PI_VERSION"] != "1.5.2" {
		t.Fatal("ArgsFor aliased the source map")
	}
	next := pins.WithAgent("pi", AgentPin{Version: "2.0.0", Args: map[string]string{"PI_VERSION": "2.0.0"}})
	next.Agents["pi"].Args["PI_VERSION"] = "3.0.0"
	if pins.Agents["pi"].Version != "1.5.2" {
		t.Fatal("WithAgent modified the source pin set")
	}
	if pins.ArgsFor("unknown") != nil {
		t.Fatal("ArgsFor returned pins for an unknown agent")
	}
	if pins.ArgsFor("base")["ALPINE_IMAGE"] == "" {
		t.Fatal("ArgsFor(base) returned no Alpine image")
	}
}
