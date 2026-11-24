package policy_test

import (
	"strings"
	"testing"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
	"agentbox/internal/policy"
)

func instanceHost() (*fsx.Fake, policy.Request) {
	f := opencodeHost()
	root := testHome + "/.agentbox/instances"
	f.Mkdir(root)
	f.Paths[root] = fsx.FakeEntry{Dir: true, Mode: 0o700}
	f.Mkdir(root + "/dev/home")
	f.Paths[root+"/dev/home"] = fsx.FakeEntry{Dir: true, Mode: 0o700}
	f.Mkdir(root + "/dev/config")
	f.Write(root+"/dev/config/opencode.json", []byte(`{"model":"instance"}`))
	f.Paths[root+"/dev/config"] = fsx.FakeEntry{Dir: true, Mode: 0o700}
	return f, policy.Request{
		LaunchDir:    testHome + "/project",
		InstanceName: "dev",
		InstanceRoot: root,
		InstanceHome: root + "/dev/home",
		ConfigRoot:   root + "/dev/config",
	}
}

func TestInstanceResolveUsesClonedConfig(t *testing.T) {
	f, req := instanceHost()
	spec := mustResolve(t, f, "opencode", req)
	if spec.Instance != "dev" || spec.ConfigSource != "instance" || !spec.UserConfig {
		t.Fatalf("unexpected instance decision: %+v", spec)
	}
	if spec.InstanceHome != req.InstanceHome {
		t.Fatalf("InstanceHome = %q, want %q", spec.InstanceHome, req.InstanceHome)
	}
	if spec.Hostname != "agentbox-dev" {
		t.Fatalf("Hostname = %q, want agentbox-dev", spec.Hostname)
	}
	var state, config bool
	for _, m := range spec.Mounts {
		if m.Host == req.InstanceHome && m.Dest == agent.ContainerHome && m.Access == policy.RW && m.Origin == "state" {
			state = true
		}
		if m.Host == req.ConfigRoot+"/opencode.json" && m.Origin == "agent-config" {
			config = true
		}
		if strings.HasPrefix(m.Host, testHome+"/.config/opencode") {
			t.Fatalf("host config must not be mounted for an instance: %+v", m)
		}
	}
	if !state {
		t.Fatalf("persistent HOME mount missing: %+v", spec.Mounts)
	}
	if !config {
		t.Fatalf("cloned config mount missing: %+v", spec.Mounts)
	}
}

func TestInstanceHostnameSanitizesUnderscore(t *testing.T) {
	f, req := instanceHost()
	req.InstanceName = "my_dev"
	req.InstanceHome = req.InstanceRoot + "/my_dev/home"
	req.ConfigRoot = req.InstanceRoot + "/my_dev/config"
	f.Mkdir(req.InstanceHome)
	f.Paths[req.InstanceHome] = fsx.FakeEntry{Dir: true, Mode: 0o700}
	f.Mkdir(req.ConfigRoot)
	f.Paths[req.ConfigRoot] = fsx.FakeEntry{Dir: true, Mode: 0o700}
	spec := mustResolve(t, f, "opencode", req)
	if spec.Hostname != "agentbox-my-dev" {
		t.Fatalf("Hostname = %q, want agentbox-my-dev", spec.Hostname)
	}
}

func TestInstanceWithoutPersistentHome(t *testing.T) {
	f, req := instanceHost()
	req.InstanceHome = ""
	spec := mustResolve(t, f, "opencode", req)
	if spec.InstanceHome != "" {
		t.Fatalf("InstanceHome = %q, want empty", spec.InstanceHome)
	}
	for _, m := range spec.Mounts {
		if m.Dest == agent.ContainerHome {
			t.Fatalf("policy must not add a HOME mount without an instance home: %+v", m)
		}
	}
}

func TestInstanceNoUserConfig(t *testing.T) {
	f, req := instanceHost()
	req.NoUserConfig = true
	spec := mustResolve(t, f, "opencode", req)
	if spec.ConfigSource != "none" || spec.UserConfig {
		t.Fatalf("expected no config, got %+v", spec)
	}
	for _, m := range spec.Mounts {
		if strings.HasPrefix(m.Host, req.ConfigRoot) {
			t.Fatalf("config must not be mounted under --no-user-config: %+v", m)
		}
	}
}

func TestInstanceRefusesBadPaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(f *fsx.Fake, req *policy.Request)
	}{
		{
			name: "bad name",
			mutate: func(_ *fsx.Fake, req *policy.Request) {
				req.InstanceName = "Dev"
			},
		},
		{
			name: "empty root",
			mutate: func(_ *fsx.Fake, req *policy.Request) {
				req.InstanceRoot = ""
			},
		},
		{
			name: "relative root",
			mutate: func(_ *fsx.Fake, req *policy.Request) {
				req.InstanceRoot = "instances"
			},
		},
		{
			name: "root mode",
			mutate: func(f *fsx.Fake, req *policy.Request) {
				f.Paths[req.InstanceRoot] = fsx.FakeEntry{Dir: true, Mode: 0o755}
			},
		},
		{
			name: "root symlink",
			mutate: func(f *fsx.Fake, req *policy.Request) {
				f.Symlink(testHome+"/.config", req.InstanceRoot)
			},
		},
		{
			name: "home path",
			mutate: func(_ *fsx.Fake, req *policy.Request) {
				req.InstanceHome = req.InstanceRoot + "/dev/other"
			},
		},
		{
			name: "home mode",
			mutate: func(f *fsx.Fake, req *policy.Request) {
				f.Paths[req.InstanceHome] = fsx.FakeEntry{Dir: true, Mode: 0o755}
			},
		},
		{
			name: "home symlink",
			mutate: func(f *fsx.Fake, req *policy.Request) {
				f.Symlink(testHome+"/.ssh", req.InstanceHome)
			},
		},
		{
			name: "config path",
			mutate: func(_ *fsx.Fake, req *policy.Request) {
				req.ConfigRoot = req.InstanceRoot + "/dev/other"
			},
		},
		{
			name: "config mode",
			mutate: func(f *fsx.Fake, req *policy.Request) {
				f.Paths[req.ConfigRoot] = fsx.FakeEntry{Dir: true, Mode: 0o755}
			},
		},
		{
			name: "config symlink",
			mutate: func(f *fsx.Fake, req *policy.Request) {
				f.Symlink(testHome+"/.config/opencode", req.ConfigRoot)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, req := instanceHost()
			tc.mutate(f, &req)
			_, err := resolve(t, f, "opencode", req, nil)
			wantRefusal(t, err)
		})
	}
}

func TestValidateInstanceName(t *testing.T) {
	for _, name := range []string{"a", "dev", "my_dev", "a-b", "0x", strings.Repeat("a", 32)} {
		if err := policy.ValidateInstanceName(name); err != nil {
			t.Fatalf("ValidateInstanceName(%q) = %v", name, err)
		}
	}
	for _, name := range []string{"", "A", "-a", "_a", "a.b", "a/b", "../x", strings.Repeat("a", 33)} {
		if err := policy.ValidateInstanceName(name); err == nil {
			t.Fatalf("ValidateInstanceName(%q) should fail", name)
		}
	}
}

func TestValidateInstanceRoot(t *testing.T) {
	if err := policy.ValidateInstanceRoot(testHome, testHome+"/.agentbox/instances"); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"/", testHome, testHome + "/.ssh/store", "relative"} {
		if err := policy.ValidateInstanceRoot(testHome, root); err == nil {
			t.Fatalf("ValidateInstanceRoot(%q) should fail", root)
		}
	}
}

func TestClonePlanUsesSameAllowList(t *testing.T) {
	f := opencodeHost()
	reg := agent.New(testHome)
	def, err := reg.Get("opencode")
	if err != nil {
		t.Fatal(err)
	}
	seeds, mounts, refs := policy.NewResolver(f, envFunc(nil)).ClonePlan(def, false)
	if len(seeds) != 0 {
		t.Fatalf("opencode should clone mounts, not seeds: %+v", seeds)
	}
	var sawConfig, sawSymlink bool
	for _, m := range mounts {
		if strings.HasSuffix(m.Host, "/opencode.json") {
			sawConfig = true
		}
		if m.Origin == "symlink" {
			sawSymlink = true
		}
	}
	if !sawConfig || !sawSymlink {
		t.Fatalf("unexpected clone plan: %+v (refusals %+v)", mounts, refs)
	}
}
