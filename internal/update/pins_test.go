package update

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func validPinsYAML() string {
	return fmt.Sprintf(`version: 1
base:
  args:
    DEBIAN_IMAGE: docker.io/library/debian:stable-slim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
agents:
  pi:
    version: 1.5.2
    args:
      PI_VERSION: 1.5.2
      PI_SHA512_HEX: %s
`, strings.Repeat("b", 128))
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
		{"unknown key", strings.Replace(validPinsYAML(), "version: 1", "version: 1\nunexpected: true", 1)},
		{"bad version", strings.Replace(validPinsYAML(), "version: 1", "version: 2", 1)},
		{"bad agent version", strings.Replace(validPinsYAML(), "pi:\n    version: 1.5.2", "pi:\n    version: latest", 1)},
		{"bad digest", strings.Replace(validPinsYAML(), strings.Repeat("b", 128), "deadbeef", 1)},
		{"empty arg", strings.Replace(validPinsYAML(), "PI_VERSION: 1.5.2", "PI_VERSION: \"\"", 1)},
		{"newline in arg", strings.Replace(validPinsYAML(), "PI_VERSION: 1.5.2", `PI_VERSION: "1.5.2\nx"`, 1)},
		{"no args", strings.Replace(validPinsYAML(), "  args:\n    DEBIAN_IMAGE: docker.io/library/debian:stable-slim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "", 1)},
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
	if pins.ArgsFor("base")["DEBIAN_IMAGE"] == "" {
		t.Fatal("ArgsFor(base) returned no base image")
	}
}
