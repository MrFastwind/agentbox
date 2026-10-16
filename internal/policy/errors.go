package policy

import (
	"fmt"
	"strings"
)

// RefusalKind classifies why something was denied.
type RefusalKind string

const (
	RefusalLaunchDir RefusalKind = "launch-dir"
	RefusalMount     RefusalKind = "mount"
	RefusalSymlink   RefusalKind = "symlink"
	RefusalEnv       RefusalKind = "env"
	RefusalNetwork   RefusalKind = "network"
	RefusalSeed      RefusalKind = "seed"
	RefusalResource  RefusalKind = "resource"
	RefusalAgent     RefusalKind = "agent"
	RefusalImage     RefusalKind = "image"
)

// Refusal is a denied decision. Fatal refusals abort the run; non-fatal ones are
// recorded so that doctor and --print-argv can show why something did not
// happen, rather than leaving the user to guess.
type Refusal struct {
	Kind    RefusalKind
	Subject string
	Reason  string
	Fatal   bool
}

func (r Refusal) String() string {
	sev := "warning"
	if r.Fatal {
		sev = "refused"
	}
	return fmt.Sprintf("%s [%s] %s: %s", sev, r.Kind, r.Subject, r.Reason)
}

// Error aggregates fatal refusals.
type Error struct {
	Refusals []Refusal
}

func (e *Error) Error() string {
	parts := make([]string, 0, len(e.Refusals))
	for _, r := range e.Refusals {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, "\n")
}

func refusal(kind RefusalKind, subject, reason string) Refusal {
	return Refusal{Kind: kind, Subject: subject, Reason: reason, Fatal: true}
}

func warn(kind RefusalKind, subject, reason string) Refusal {
	return Refusal{Kind: kind, Subject: subject, Reason: reason}
}

func fatalError(rs []Refusal) *Error {
	var fatals []Refusal
	for _, r := range rs {
		if r.Fatal {
			fatals = append(fatals, r)
		}
	}
	if len(fatals) == 0 {
		return nil
	}
	return &Error{Refusals: fatals}
}
