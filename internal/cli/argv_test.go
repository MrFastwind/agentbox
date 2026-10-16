package cli_test

import (
	"reflect"
	"testing"

	"container-agent/internal/cli"
)

func TestDefaultIsPassThrough(t *testing.T) {
	inv := cli.Split([]string{"npm", "test"})
	if !inv.IsRun() {
		t.Fatalf("expected a run invocation, got subcommand %q", inv.Subcommand)
	}
	if inv.Explicit {
		t.Fatal("Explicit should be false")
	}
	if !reflect.DeepEqual(inv.Args, []string{"npm", "test"}) {
		t.Fatalf("unexpected args: %v", inv.Args)
	}
}

func TestFlagsThenCommand(t *testing.T) {
	inv := cli.Split([]string{"--agent", "opencode", "npm", "test"})
	if !inv.IsRun() {
		t.Fatal("expected a run invocation")
	}
	// The flag package is what separates flags from the command; Split must not
	// interpret them.
	if !reflect.DeepEqual(inv.Args, []string{"--agent", "opencode", "npm", "test"}) {
		t.Fatalf("unexpected args: %v", inv.Args)
	}
}

func TestReservedWordsAreSubcommands(t *testing.T) {
	for _, name := range []string{"exec", "images", "doctor", "version"} {
		inv := cli.Split([]string{name})
		if inv.Subcommand != name {
			t.Fatalf("%s: expected subcommand %q, got %q", name, name, inv.Subcommand)
		}
	}
}

// "container-agent exec foo" is spelled identically whether exec is the
// subcommand or the program to run. "--" is the escape.
func TestDoubleDashEscapesReservedWord(t *testing.T) {
	inv := cli.Split([]string{"--", "exec", "foo"})
	if !inv.IsRun() {
		t.Fatalf("expected a run invocation, got subcommand %q", inv.Subcommand)
	}
	if !inv.Explicit {
		t.Fatal("Explicit should be true after --")
	}
	if !reflect.DeepEqual(inv.Args, []string{"exec", "foo"}) {
		t.Fatalf("unexpected args: %v", inv.Args)
	}
}

// A reserved word that is not first is a plain command.
func TestReservedWordNotFirstIsPassThrough(t *testing.T) {
	inv := cli.Split([]string{"--agent", "pi", "doctor"})
	if !inv.IsRun() {
		t.Fatalf("expected a run invocation, got subcommand %q", inv.Subcommand)
	}
	if !reflect.DeepEqual(inv.Args, []string{"--agent", "pi", "doctor"}) {
		t.Fatalf("unexpected args: %v", inv.Args)
	}
}

func TestEmptyArgv(t *testing.T) {
	inv := cli.Split(nil)
	if !inv.IsRun() || len(inv.Args) != 0 {
		t.Fatalf("unexpected invocation: %+v", inv)
	}
}
