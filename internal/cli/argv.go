// Package cli splits the command line into a reserved subcommand or a
// pass-through invocation.
//
// The program's default invocation is the command: "agentbox npm test"
// runs npm test inside the sandbox. That collides with subcommands, because
// "agentbox exec foo" is a legal way to spell both "run the exec
// subcommand" and "run the program exec inside the container".
//
// The rule is one sentence: reserved words are recognized only as the first
// argument, and "--" escapes them. So "agentbox -- exec foo" always means
// the program, and there is no heuristic to guess wrong.
//
// Flags must precede the pass-through command; anything after the first
// non-flag argument is passed through untouched, which is what the flag
// package already does.
package cli

// reservedSubcommands are recognized in first position only.
var reservedSubcommands = map[string]bool{
	"create":  true,
	"exec":    true,
	"images":  true,
	"doctor":  true,
	"inspect": true,
	"list":    true,
	"open":    true,
	"refresh": true,
	"remove":  true,
	"version": true,
}

// Invocation is a parsed command line.
type Invocation struct {
	// Subcommand is empty for the default run invocation.
	Subcommand string
	// Args is the remainder: the subcommand's arguments, or the run
	// invocation's argv.
	Args []string
	// Explicit is true when "--" was used, meaning Args are wholly a command to
	// run in the container and must not be parsed as flags.
	Explicit bool
}

// IsRun reports whether this is the default run invocation.
func (i Invocation) IsRun() bool { return i.Subcommand == "" }

// Reserved reports whether name is a reserved subcommand.
func Reserved(name string) bool { return reservedSubcommands[name] }

// Split parses argv (excluding the program name).
func Split(argv []string) Invocation {
	if len(argv) > 0 {
		switch {
		case argv[0] == "--":
			return Invocation{Args: argv[1:], Explicit: true}
		case reservedSubcommands[argv[0]]:
			return Invocation{Subcommand: argv[0], Args: argv[1:]}
		}
	}
	return Invocation{Args: argv}
}
