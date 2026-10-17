package policy_test

import (
	"testing"

	"agentbox/internal/fsx"
	"agentbox/internal/policy"
)

func mount(host, dest string, a policy.Access, origin string) policy.ResolvedMount {
	return policy.ResolvedMount{Host: host, Dest: dest, Access: a, Origin: origin}
}

func TestRevalidateAcceptsStableMounts(t *testing.T) {
	f := fsx.NewFake("/home/u", "/home/u/project")
	f.Mkdir("/home/u/project")
	f.Mkdir("/home/u/.config/opencode")
	spec := &policy.ResolvedSpec{Mounts: []policy.ResolvedMount{
		mount("/home/u/project", "/workspace", policy.RW, "launch-dir"),
		mount("/home/u/.config/opencode", "/home/agent/.config/opencode", policy.RO, "agent-config"),
	}}
	if err := policy.Revalidate(spec, f); err != nil {
		t.Fatalf("stable mounts must pass re-validation: %v", err)
	}
}

// A symlink planted or swapped after resolution makes the path resolve somewhere
// other than what was validated; that is exactly the TOCTOU the second pass
// exists to catch.
func TestRevalidateRefusesSwappedSymlink(t *testing.T) {
	f := fsx.NewFake("/home/u", "/home/u/project")
	f.Mkdir("/home/u/evil")
	f.Symlink("/home/u/evil", "/home/u/project")
	spec := &policy.ResolvedSpec{Mounts: []policy.ResolvedMount{
		mount("/home/u/project", "/workspace", policy.RW, "launch-dir"),
	}}
	if err := policy.Revalidate(spec, f); err == nil {
		t.Fatal("a mount whose path now resolves elsewhere must be refused")
	}
}

// A writable parent lets the sandbox replace the read-only target after the
// check, so a read-only mount inside a writable one is refused.
func TestRevalidateRefusesReadOnlyInsideWritable(t *testing.T) {
	f := fsx.NewFake("/home/u", "/home/u/project")
	f.Mkdir("/home/u/project")
	f.Mkdir("/home/u/project/vendor")
	spec := &policy.ResolvedSpec{Mounts: []policy.ResolvedMount{
		mount("/home/u/project", "/workspace", policy.RW, "launch-dir"),
		mount("/home/u/project/vendor", "/vendor", policy.RO, "extra"),
	}}
	if err := policy.Revalidate(spec, f); err == nil {
		t.Fatal("a read-only mount inside a writable mount must be refused")
	}
}

// The state and seed mounts are created by the session after resolution; they
// are program-owned and must not be re-checked against a user-controlled FS.
func TestRevalidateSkipsProgramOwnedOrigins(t *testing.T) {
	f := fsx.NewFake("/home/u", "/home/u/project")
	spec := &policy.ResolvedSpec{Mounts: []policy.ResolvedMount{
		mount("/does/not/exist/state", "/home/agent", policy.RW, "state"),
		mount("/does/not/exist/seeds", "/run/agentbox/seeds", policy.RO, "seed"),
	}}
	if err := policy.Revalidate(spec, f); err != nil {
		t.Fatalf("program-owned mounts must be skipped: %v", err)
	}
}

func TestRevalidateRefusesVanishedMount(t *testing.T) {
	f := fsx.NewFake("/home/u", "/home/u/project")
	spec := &policy.ResolvedSpec{Mounts: []policy.ResolvedMount{
		mount("/home/u/gone", "/gone", policy.RO, "extra"),
	}}
	if err := policy.Revalidate(spec, f); err == nil {
		t.Fatal("a mount whose host path has vanished must be refused")
	}
}

func TestResolverRevalidateDelegates(t *testing.T) {
	f := fsx.NewFake("/home/u", "/home/u/project")
	f.Mkdir("/home/u/project")
	r := policy.NewResolver(f, func(string) (string, bool) { return "", false })
	spec := &policy.ResolvedSpec{Mounts: []policy.ResolvedMount{
		mount("/home/u/project", "/workspace", policy.RW, "launch-dir"),
	}}
	if err := r.Revalidate(spec); err != nil {
		t.Fatalf("Resolver.Revalidate: %v", err)
	}
}
