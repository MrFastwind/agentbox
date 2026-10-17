package policy_test

import (
	"errors"
	"strings"
	"testing"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
	"agentbox/internal/policy"
)

const testHome = "/home/u"

func envFunc(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// opencodeHost is the host layout opencode actually has: a static config
// directory whose skills entry is a symlink out of that directory, plus a state
// directory holding credentials that must never be mounted.
func opencodeHost() *fsx.Fake {
	f := fsx.NewFake(testHome, testHome+"/project")
	f.Mkdir(testHome + "/project")

	f.Mkdir(testHome + "/.ssh")
	f.Write(testHome+"/.ssh/id_ed25519", []byte("PRIVATE KEY"))

	f.Mkdir(testHome + "/.local/share/opencode")
	f.Write(testHome+"/.local/share/opencode/auth.json", []byte(`{"tok":"live"}`))
	f.Write(testHome+"/.local/share/opencode/account.json", []byte(`{"plan":"pro"}`))

	f.Mkdir(testHome + "/.config/opencode/agents")
	f.Write(testHome+"/.config/opencode/opencode.json", []byte(`{"model":"m"}`))
	f.Write(testHome+"/.config/opencode/auth.json", []byte(`{"tok":"in-config"}`))

	f.Mkdir(testHome + "/media/agent-skills/skills")
	f.Symlink(testHome+"/media/agent-skills/skills", testHome+"/.config/opencode/skills")

	return f
}

// piHost mirrors pi v0.87.1: config, credentials and state in one directory.
func piHost() *fsx.Fake {
	f := fsx.NewFake(testHome, testHome+"/project")
	f.Mkdir(testHome + "/project")
	f.Mkdir(testHome + "/.pi/agent")
	d := testHome + "/.pi/agent"

	f.Write(d+"/auth.json", []byte(`{"anthropic":{"type":"api_key","key":"sk-auth"}}`))
	f.Write(d+"/settings.json", []byte(`{"theme":"dark","apiKeys":{"anthropic":"sk-settings"}}`))
	f.Write(d+"/models.json", []byte(`{"providers":{"openai":{"apiKey":"sk-models","model":"gpt"}}}`))
	f.Write(d+"/models-store.json", []byte(`{"openai":{"model":"gpt"}}`))
	f.Write(d+"/oauth.json", []byte(`{"x":{"access":"a","refresh":"r"}}`))
	f.Write(d+"/trust.json", []byte(`{"/home/u":true}`))
	f.Mkdir(d + "/sessions")

	return f
}

func resolve(t *testing.T, f *fsx.Fake, agentName string, req policy.Request, env map[string]string) (*policy.ResolvedSpec, error) {
	t.Helper()
	reg := agent.New(testHome)
	def, err := reg.Get(agentName)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if req.NoUserConfig {
		if def, err = reg.WithoutUserConfig(agentName); err != nil {
			t.Fatalf("registry: %v", err)
		}
	}
	return policy.NewResolver(f, envFunc(env)).Resolve(def, req)
}

func mustResolve(t *testing.T, f *fsx.Fake, agentName string, req policy.Request) *policy.ResolvedSpec {
	t.Helper()
	spec, err := resolve(t, f, agentName, req, nil)
	if err != nil {
		t.Fatalf("expected resolution to succeed, got: %v", err)
	}
	return spec
}

func wantRefusal(t *testing.T, err error) *policy.Error {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got none")
	}
	var rerr *policy.Error
	if !errors.As(err, &rerr) {
		t.Fatalf("expected a policy refusal, got %T: %v", err, err)
	}
	return rerr
}

func hasMount(spec *policy.ResolvedSpec, pred func(policy.ResolvedMount) bool) bool {
	for _, m := range spec.Mounts {
		if pred(m) {
			return true
		}
	}
	return false
}

// --- launch directory -------------------------------------------------------

func TestLaunchDirInsideHomeIsAllowed(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{LaunchDir: testHome + "/project"})
	if !hasMount(spec, func(m policy.ResolvedMount) bool {
		return m.Dest == policy.ContainerWorkdir && m.Access == policy.RW && m.Origin == "launch-dir"
	}) {
		t.Fatalf("expected the launch directory mounted rw at %s, got %+v", policy.ContainerWorkdir, spec.Mounts)
	}
}

func TestLaunchDirIsHomeRefused(t *testing.T) {
	_, err := resolve(t, opencodeHost(), "opencode", policy.Request{LaunchDir: testHome}, nil)
	wantRefusal(t, err)
}

func TestLaunchDirIsRootRefused(t *testing.T) {
	_, err := resolve(t, opencodeHost(), "opencode", policy.Request{LaunchDir: "/"}, nil)
	wantRefusal(t, err)
}

// A directory that merely *contains* a protected path is as unsafe as the
// protected path itself: mounting /home exposes /home/u/.ssh.
func TestLaunchDirContainingProtectedPathRefused(t *testing.T) {
	f := opencodeHost()
	_, err := resolve(t, f, "opencode", policy.Request{LaunchDir: "/home"}, nil)
	wantRefusal(t, err)
}

func TestLaunchDirSymlinkedToHomeRefused(t *testing.T) {
	f := opencodeHost()
	// The literal string looks harmless; resolution is what matters.
	f.Symlink(testHome, testHome+"/project/link-to-home")
	_, err := resolve(t, f, "opencode", policy.Request{LaunchDir: testHome + "/project/link-to-home"}, nil)
	wantRefusal(t, err)
}

// --- explicit mounts --------------------------------------------------------

func TestExplicitMountOfSSHRefused(t *testing.T) {
	_, err := resolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir:   testHome + "/project",
		ExtraMounts: []string{testHome + "/.ssh:/keys:ro"},
	}, nil)
	wantRefusal(t, err)
}

func TestExplicitMountSymlinkToSSHRefused(t *testing.T) {
	f := opencodeHost()
	f.Symlink(testHome+"/.ssh", testHome+"/project/innocent")
	_, err := resolve(t, f, "opencode", policy.Request{
		LaunchDir:   testHome + "/project",
		ExtraMounts: []string{testHome + "/project/innocent:/keys:ro"},
	}, nil)
	wantRefusal(t, err)
}

func TestExplicitMountDefaultsToReadOnly(t *testing.T) {
	f := opencodeHost()
	f.Mkdir(testHome + "/project/data")
	spec := mustResolve(t, f, "opencode", policy.Request{
		LaunchDir:   testHome + "/project",
		ExtraMounts: []string{testHome + "/project/data:/data"},
	})
	if !hasMount(spec, func(m policy.ResolvedMount) bool {
		return m.Dest == "/data" && m.Access == policy.RO
	}) {
		t.Fatalf("expected a read-only extra mount, got %+v", spec.Mounts)
	}
}

func TestOnlyOneWritableMount(t *testing.T) {
	f := opencodeHost()
	spec := mustResolve(t, f, "opencode", policy.Request{LaunchDir: testHome + "/project"})
	rw := 0
	for _, m := range spec.Mounts {
		if m.Access == policy.RW {
			rw++
		}
	}
	if rw != 1 {
		t.Fatalf("expected exactly one writable mount, got %d: %+v", rw, spec.Mounts)
	}
}

// --- opencode config mounting ----------------------------------------------

func TestConfigCredentialsNotMounted(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{LaunchDir: testHome + "/project"})
	for _, m := range spec.Mounts {
		if strings.Contains(m.Host, "auth.json") || strings.Contains(m.Host, "account.json") {
			t.Fatalf("credential file was mounted: %+v", m)
		}
	}
	if hasMount(spec, func(m policy.ResolvedMount) bool {
		return strings.Contains(m.Host, ".local/share")
	}) {
		t.Fatal("state directory was mounted")
	}
}

func TestConfigEntriesAreMountedReadOnly(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{LaunchDir: testHome + "/project"})
	if !hasMount(spec, func(m policy.ResolvedMount) bool {
		return strings.HasSuffix(m.Dest, "/opencode.json") && m.Access == policy.RO
	}) {
		t.Fatalf("expected opencode.json mounted read-only, got %+v", spec.Mounts)
	}
}

// The skills entry is a symlink out of the config directory. It must be
// materialized at the link's own path, not left dangling.
func TestConfigSymlinkResolvedWithinPrefixes(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{LaunchDir: testHome + "/project"})
	if !hasMount(spec, func(m policy.ResolvedMount) bool {
		return strings.HasSuffix(m.Dest, "/skills") &&
			m.Host == testHome+"/media/agent-skills/skills" &&
			m.Origin == "symlink"
	}) {
		t.Fatalf("expected the skills symlink resolved and mounted at its own path, got %+v", spec.Mounts)
	}
}

// A symlink pointing outside the allowed prefixes is skipped, not followed, and
// not fatal: not mounting a path is always safe, and a link to another volume is
// a legitimate layout.
func TestConfigSymlinkOutsidePrefixesSkipped(t *testing.T) {
	f := opencodeHost()
	f.Mkdir("/etc")
	f.Write("/etc/passwd", []byte("root:x:0:0"))
	f.Symlink("/etc/passwd", testHome+"/.config/opencode/escape")

	spec := mustResolve(t, f, "opencode", policy.Request{LaunchDir: testHome + "/project"})

	for _, m := range spec.Mounts {
		if strings.Contains(m.Host, "/etc/passwd") {
			t.Fatalf("an out-of-prefix symlink target was mounted: %+v", m)
		}
		if strings.HasSuffix(m.Dest, "/escape") {
			t.Fatalf("the escaping symlink was mounted: %+v", m)
		}
	}
	warned := false
	for _, r := range spec.Refusals {
		if r.Kind == policy.RefusalSymlink && !r.Fatal && strings.Contains(r.Reason, "outside the allowed prefixes") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected an auditable warning about the skipped symlink; got %+v", spec.Refusals)
	}
}

// The realistic layout: the home directory reaches outside itself through a
// symlink (~/media -> /media/u/data), so a home-relative config link resolves to
// a path that is NOT under realpath(home). The logical arm of the bound has to
// accept it — otherwise the link is silently skipped and the agent simply has no
// skills — and the mount is still read-only.
func TestConfigSymlinkThroughHomeIndirectionFollowed(t *testing.T) {
	f := fsx.NewFake(testHome, testHome+"/project")
	f.Mkdir(testHome + "/project")
	f.Mkdir(testHome + "/.config/opencode")
	f.Write(testHome+"/.config/opencode/opencode.json", []byte(`{"model":"m"}`))

	f.Mkdir("/media/u/data/skills")
	f.Symlink("/media/u/data", testHome+"/media")
	f.Symlink(testHome+"/media/skills", testHome+"/.config/opencode/skills")

	spec := mustResolve(t, f, "opencode", policy.Request{LaunchDir: testHome + "/project"})

	if !hasMount(spec, func(m policy.ResolvedMount) bool {
		return m.Origin == "symlink" &&
			m.Access == policy.RO &&
			m.Host == "/media/u/data/skills" &&
			strings.HasSuffix(m.Dest, "/skills")
	}) {
		t.Fatalf("a home-relative link resolving outside realpath(home) must be followed "+
			"(mounts=%+v refusals=%+v)", spec.Mounts, spec.Refusals)
	}
}

// A relative link written into the config directory, crossing a home symlink out
// to another volume: the resolved target leaves home, the link as written does
// not. This is the branch that reads the link back rather than trusting the
// resolved path alone.
func TestConfigRelativeSymlinkThroughHomeIndirectionFollowed(t *testing.T) {
	f := fsx.NewFake(testHome, testHome+"/project")
	f.Mkdir(testHome + "/project")
	f.Mkdir(testHome + "/.config/opencode")
	f.Write(testHome+"/.config/opencode/opencode.json", []byte(`{"model":"m"}`))

	f.Write("/media/u/data/skill.json", []byte(`{}`))
	f.Symlink("/media/u/data", testHome+"/outside")
	f.Symlink("../../outside/skill.json", testHome+"/.config/opencode/rel")

	spec := mustResolve(t, f, "opencode", policy.Request{LaunchDir: testHome + "/project"})

	if !hasMount(spec, func(m policy.ResolvedMount) bool {
		return m.Origin == "symlink" &&
			m.Host == "/media/u/data/skill.json" &&
			strings.HasSuffix(m.Dest, "/rel")
	}) {
		t.Fatalf("a relative link crossing a home symlink must be followed "+
			"(mounts=%+v refusals=%+v)", spec.Mounts, spec.Refusals)
	}
}

// The prefix bound only establishes "inside the user's home", and home is where
// the credentials live. A config link into ~/.ssh passes that bound and must
// still be refused by the deny-list, which is the rule that actually separates
// configuration from credentials.
func TestConfigSymlinkToSensitiveDirDenied(t *testing.T) {
	f := opencodeHost()
	f.Symlink(testHome+"/.ssh", testHome+"/.config/opencode/notes")

	spec := mustResolve(t, f, "opencode", policy.Request{LaunchDir: testHome + "/project"})

	for _, m := range spec.Mounts {
		if strings.HasSuffix(m.Dest, "/notes") {
			t.Fatalf("a symlink pointing at ~/.ssh must not be mounted: %+v", m)
		}
	}
	warned := false
	for _, r := range spec.Refusals {
		if r.Kind == policy.RefusalSymlink && !r.Fatal && strings.Contains(r.Reason, "deny-listed") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected a deny-list warning for the ~/.ssh symlink, got %+v", spec.Refusals)
	}
}

// doctor asks the resolver what mounting the config directory would do, with no
// request and no launch directory, so a skipped link is visible before a run.
func TestAgentConfigDecisionsShowsFollowedAndSkipped(t *testing.T) {
	f := opencodeHost()
	f.Mkdir("/etc")
	f.Write("/etc/passwd", []byte("root:x:0:0"))
	f.Symlink("/etc/passwd", testHome+"/.config/opencode/escape")

	def, err := agent.New(testHome).Get("opencode")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	mounts, refs := policy.NewResolver(f, envFunc(nil)).AgentConfigDecisions(def)

	followed := false
	for _, m := range mounts {
		if m.Origin == "symlink" && strings.HasSuffix(m.Dest, "/skills") {
			followed = true
		}
	}
	if !followed {
		t.Fatalf("doctor must see the followed skills link, got mounts=%+v", mounts)
	}
	skipped := false
	for _, r := range refs {
		if r.Kind == policy.RefusalSymlink && !r.Fatal && strings.Contains(r.Reason, "outside the allowed prefixes") {
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("doctor must see the skipped link, got refusals=%+v", refs)
	}
}

// --- pi seeding -------------------------------------------------------------

func TestPiSeedsOnlyAllowListedFiles(t *testing.T) {
	spec := mustResolve(t, piHost(), "pi", policy.Request{LaunchDir: testHome + "/project"})

	got := map[string]bool{}
	for _, s := range spec.Seed {
		got[s.Rel] = true
	}
	for _, forbidden := range []string{
		"auth.json", "oauth.json", "oauth.json.migrated", "trust.json",
	} {
		if got[forbidden] {
			t.Fatalf("%s must never be seeded", forbidden)
		}
	}
	for _, want := range []string{"settings.json", "models.json", "models-store.json"} {
		if !got[want] {
			t.Fatalf("%s should have been seeded; seeded set is %v", want, got)
		}
	}
}

func TestPiStripsCredentialKeys(t *testing.T) {
	spec := mustResolve(t, piHost(), "pi", policy.Request{LaunchDir: testHome + "/project"})

	var settings, models *policy.SeededFile
	for i := range spec.Seed {
		switch spec.Seed[i].Rel {
		case "settings.json":
			settings = &spec.Seed[i]
		case "models.json":
			models = &spec.Seed[i]
		}
	}
	if settings == nil || models == nil {
		t.Fatal("expected settings.json and models.json to be seeded")
	}

	for _, tc := range []struct {
		name string
		sf   *policy.SeededFile
		leak string
		keep string
	}{
		{"settings.json", settings, "sk-settings", "dark"},
		{"models.json", models, "sk-models", "gpt"},
	} {
		if strings.Contains(string(tc.sf.Data), tc.leak) {
			t.Errorf("%s: credential leaked into seeded bytes", tc.name)
		}
		if !strings.Contains(string(tc.sf.Data), tc.keep) {
			t.Errorf("%s: non-credential configuration was lost (want %q)", tc.name, tc.keep)
		}
		if len(tc.sf.RemovedKeys) == 0 {
			t.Errorf("%s: expected removed keys to be recorded for audit", tc.name)
		}
	}
}

// A file that is safe by name but not by content must still fail closed.
func TestSeedContentAssertionFailsClosed(t *testing.T) {
	f := piHost()
	f.Write(testHome+"/.pi/agent/models-store.json", []byte(`{"openai":{"apiKey":"sk-sneaky"}}`))
	_, err := resolve(t, f, "pi", policy.Request{LaunchDir: testHome + "/project"}, nil)
	rerr := wantRefusal(t, err)
	if !strings.Contains(rerr.Error(), "credential-shaped keys survived") {
		t.Fatalf("expected a content-assertion refusal, got: %v", rerr)
	}
}

func TestPiDoesNotMountItsConfigDirectory(t *testing.T) {
	spec := mustResolve(t, piHost(), "pi", policy.Request{LaunchDir: testHome + "/project"})
	for _, m := range spec.Mounts {
		if strings.Contains(m.Host, ".pi/agent") {
			t.Fatalf("pi's config directory must never be mounted: %+v", m)
		}
	}
}

// --- environment ------------------------------------------------------------

func TestNoCredentialsCrossByDefault(t *testing.T) {
	host := map[string]string{
		"ANTHROPIC_API_KEY": "sk-live",
		"OPENCODE_API_KEY":  "sk-live",
		"TERM":              "xterm-256color",
	}
	for _, name := range []string{"pi", "opencode"} {
		spec, err := resolve(t, opencodeHost(), name, policy.Request{LaunchDir: testHome + "/project"}, host)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, e := range spec.Env {
			if strings.Contains(e.Name, "API_KEY") {
				t.Fatalf("%s: credential %s crossed without being requested", name, e.Name)
			}
		}
	}
}

func TestAllowlistedEnvCrosses(t *testing.T) {
	spec, err := resolve(t, piHost(), "pi", policy.Request{
		LaunchDir: testHome + "/project",
		EnvNames:  []string{"ANTHROPIC_API_KEY"},
	}, map[string]string{"ANTHROPIC_API_KEY": "sk-live"})
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	found := false
	for _, e := range spec.Env {
		if e.Name == "ANTHROPIC_API_KEY" && e.Value == "sk-live" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the explicitly requested, allow-listed key to cross; got %+v", spec.Env)
	}
}

func TestNonAllowlistedEnvRefused(t *testing.T) {
	_, err := resolve(t, piHost(), "pi", policy.Request{
		LaunchDir: testHome + "/project",
		EnvNames:  []string{"SSH_AUTH_SOCK"},
	}, map[string]string{"SSH_AUTH_SOCK": "/run/agent.sock"})
	rerr := wantRefusal(t, err)
	if !strings.Contains(rerr.Error(), "allowlist") {
		t.Fatalf("expected an allowlist refusal, got: %v", rerr)
	}
}

// --- --no-user-config -------------------------------------------------------

func TestNoUserConfigReadsNothing(t *testing.T) {
	f := opencodeHost()
	spec, err := resolve(t, f, "opencode", policy.Request{
		LaunchDir:    testHome + "/project",
		NoUserConfig: true,
	}, nil)
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if spec.UserConfig {
		t.Fatal("UserConfig should be false in --no-user-config mode")
	}
	if len(spec.Seed) != 0 {
		t.Fatalf("nothing should be seeded, got %+v", spec.Seed)
	}
	for _, m := range spec.Mounts {
		if strings.Contains(m.Host, ".config") {
			t.Fatalf("no config path should be mounted, got %+v", m)
		}
	}
	if !hasMount(spec, func(m policy.ResolvedMount) bool { return m.Origin == "launch-dir" }) {
		t.Fatal("the launch directory should still be mounted")
	}
}

// --- strict configuration ---------------------------------------------------

// The same host file is mounted with a warning by default, and refused in
// strict mode. That switch is where the unanswered "is the sandboxed agent
// trusted?" question is expressed rather than guessed.
func TestStrictConfigRefusesCredentialBearingConfig(t *testing.T) {
	f := opencodeHost()
	f.Write(testHome+"/.config/opencode/service.json", []byte(`{"user":"u","password":"p"}`))

	reg := agent.New(testHome)
	def, err := reg.Get("opencode")
	if err != nil {
		t.Fatal(err)
	}

	r := policy.NewResolver(f, envFunc(nil))
	r.Strict = true
	if _, err := r.Resolve(def, policy.Request{LaunchDir: testHome + "/project"}); err == nil {
		t.Fatal("strict mode should refuse a configuration file carrying credential-shaped keys")
	} else if !strings.Contains(err.Error(), "strict mode") {
		t.Fatalf("unexpected error: %v", err)
	}

	r.Strict = false
	spec, err := r.Resolve(def, policy.Request{LaunchDir: testHome + "/project"})
	if err != nil {
		t.Fatalf("non-strict resolution should succeed: %v", err)
	}
	warned := false
	for _, ref := range spec.Refusals {
		if strings.Contains(ref.Reason, "credential-shaped keys") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("non-strict mode should record an auditable warning")
	}
}

// --- network ----------------------------------------------------------------

func TestNetworkDefaultIsNotHost(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{LaunchDir: testHome + "/project"})
	if spec.Network.Mode == "host" {
		t.Fatal("host networking must not be the default")
	}
	if spec.Network.Mode != "pasta" {
		t.Fatalf("expected pasta, got %q", spec.Network.Mode)
	}
}

func TestHostNetworkWarns(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir:   testHome + "/project",
		NetworkMode: "host",
	})
	if spec.Network.Warning == "" {
		t.Fatal("host networking must carry a warning naming the exposure")
	}
}

func TestUnknownNetworkRefused(t *testing.T) {
	_, err := resolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir:   testHome + "/project",
		NetworkMode: "bridge",
	}, nil)
	wantRefusal(t, err)
}

// --- resources --------------------------------------------------------------

func TestPidsLimitClamped(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir: testHome + "/project",
		PidsLimit: 1000000,
	})
	if spec.Limits.Pids > 32768 {
		t.Fatalf("pids limit was not clamped: %d", spec.Limits.Pids)
	}
}
