package policy_test

import (
	"testing"

	"agentbox/internal/policy"
)

func TestReadOnlyWorkspaceMountsReadOnly(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir:         testHome + "/project",
		ReadOnlyWorkspace: true,
	})
	if !hasMount(spec, func(m policy.ResolvedMount) bool {
		return m.Origin == "launch-dir" && m.Access == policy.RO && m.Dest == policy.ContainerWorkdir
	}) {
		t.Fatalf("expected a read-only workspace mount, got %+v", spec.Mounts)
	}
	for _, m := range spec.Mounts {
		if m.Origin == "launch-dir" && m.Access == policy.RW {
			t.Fatalf("--read-only-workspace still produced a writable launch mount: %+v", m)
		}
	}
}

func TestWorkspaceOverrideMountsSubdirectory(t *testing.T) {
	f := opencodeHost()
	f.Mkdir(testHome + "/project/sub")
	spec := mustResolve(t, f, "opencode", policy.Request{
		LaunchDir:         testHome + "/project",
		WorkspaceOverride: "sub",
	})
	if !hasMount(spec, func(m policy.ResolvedMount) bool {
		return m.Origin == "launch-dir" && m.Host == testHome+"/project/sub" && m.Dest == policy.ContainerWorkdir
	}) {
		t.Fatalf("expected the workspace subdirectory mounted, got %+v", spec.Mounts)
	}
}

func TestWorkspaceOverrideAbsolutePath(t *testing.T) {
	f := opencodeHost()
	f.Mkdir(testHome + "/other")
	spec := mustResolve(t, f, "opencode", policy.Request{
		LaunchDir:         testHome + "/project",
		WorkspaceOverride: testHome + "/other",
	})
	if !hasMount(spec, func(m policy.ResolvedMount) bool {
		return m.Origin == "launch-dir" && m.Host == testHome+"/other"
	}) {
		t.Fatalf("expected the absolute workspace path mounted, got %+v", spec.Mounts)
	}
}

// --workspace must not become a way around the deny-list: an escape that lands
// on a protected path is refused exactly as a launch directory would be.
func TestWorkspaceOverrideEscapeRefused(t *testing.T) {
	f := opencodeHost()
	_, err := resolve(t, f, "opencode", policy.Request{
		LaunchDir:         testHome + "/project",
		WorkspaceOverride: "../.ssh",
	}, nil)
	wantRefusal(t, err)
}
