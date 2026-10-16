package policy

import (
	"errors"
	"strings"
	"testing"

	"agentbox/internal/agent"
	"agentbox/internal/fsx"
)

// --- parseMount -------------------------------------------------------------

func TestParseMount(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		src     string
		dst     string
		access  Access
		wantErr bool
	}{
		{name: "two fields defaults ro", raw: "/a:/b", src: "/a", dst: "/b", access: RO},
		{name: "explicit ro", raw: "/a:/b:ro", src: "/a", dst: "/b", access: RO},
		{name: "explicit rw", raw: "/a:/b:rw", src: "/a", dst: "/b", access: RW},
		{name: "bad access", raw: "/a:/b:bogus", wantErr: true},
		{name: "too many fields", raw: "/a:/b:ro:extra", wantErr: true},
		{name: "too few fields", raw: "/a", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, dst, access, err := parseMount(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseMount(%q) = %q,%q,%v, want error", tc.raw, src, dst, access)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMount(%q): %v", tc.raw, err)
			}
			if src != tc.src || dst != tc.dst || access != tc.access {
				t.Fatalf("parseMount(%q) = %q,%q,%v; want %q,%q,%v", tc.raw, src, dst, access, tc.src, tc.dst, tc.access)
			}
		})
	}
}

// --- resolveLimits ----------------------------------------------------------

func TestResolveLimits(t *testing.T) {
	cases := []struct {
		name        string
		mem, cpus   string
		pids        int
		wantMem     string
		wantCPUs    string
		wantPids    int
		wantWarnSub []string
	}{
		{
			name: "empty keeps defaults",
			wantMem: defaultMemory, wantCPUs: defaultCPUs, wantPids: defaultPids,
		},
		{
			name: "valid values",
			mem: "8g", cpus: "1.5", pids: 4096,
			wantMem: "8g", wantCPUs: "1.5", wantPids: 4096,
		},
		{
			name: "bad memory falls back and warns",
			mem: "lots", wantMem: defaultMemory, wantCPUs: defaultCPUs, wantPids: defaultPids,
			wantWarnSub: []string{"memory"},
		},
		{
			name: "bad cpus falls back and warns",
			cpus: "fast", wantMem: defaultMemory, wantCPUs: defaultCPUs, wantPids: defaultPids,
			wantWarnSub: []string{"cpus"},
		},
		{
			name: "pids below the fork-bomb floor clamps up and warns",
			pids: 4, wantMem: defaultMemory, wantCPUs: defaultCPUs, wantPids: minPids,
			wantWarnSub: []string{"pids-limit"},
		},
		{
			name: "pids above the ceiling clamps down and warns",
			pids: 1 << 20, wantMem: defaultMemory, wantCPUs: defaultCPUs, wantPids: maxPids,
			wantWarnSub: []string{"pids-limit"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lim, refs := resolveLimits(tc.mem, tc.cpus, tc.pids)
			if lim.Memory != tc.wantMem || lim.CPUs != tc.wantCPUs || lim.Pids != tc.wantPids {
				t.Fatalf("resolveLimits(%q,%q,%d) = %+v; want mem=%s cpus=%s pids=%d",
					tc.mem, tc.cpus, tc.pids, lim, tc.wantMem, tc.wantCPUs, tc.wantPids)
			}
			for _, sub := range tc.wantWarnSub {
				found := false
				for _, r := range refs {
					if r.Kind == RefusalResource && strings.Contains(r.Subject, sub) {
						found = true
					}
					if r.Fatal {
						t.Fatalf("resource clamping must warn, not refuse: %+v", r)
					}
				}
				if !found {
					t.Fatalf("expected a %s warning, got %+v", sub, refs)
				}
			}
			if len(tc.wantWarnSub) == 0 && len(refs) != 0 {
				t.Fatalf("unexpected warnings: %+v", refs)
			}
		})
	}
}

// --- deny-list primitives ---------------------------------------------------

func TestDenyListContainsBoundary(t *testing.T) {
	d := NewDenyList("/home/u")
	if _, ok := d.Contains("/home/u/.ssh/id_ed25519"); !ok {
		t.Fatal("a file under ~/.ssh must be contained")
	}
	if _, ok := d.Contains("/home/u/.ssh"); !ok {
		t.Fatal("~/.ssh itself must be contained")
	}
	if _, ok := d.Contains("/home/u/project"); ok {
		t.Fatal("an ordinary project directory must not be contained")
	}
	// The / boundary must be enforced: ~/.sshfoo is not ~/.ssh.
	if _, ok := d.Contains("/home/u/.sshfoo"); ok {
		t.Fatal("prefix matching must respect the path boundary")
	}
}

func TestValidateMountRootAndAncestor(t *testing.T) {
	d := NewDenyList("/home/u")
	if err := d.ValidateMount("/"); err == nil {
		t.Fatal("the filesystem root must be refused")
	}
	if err := d.ValidateMount("/home/u"); err == nil {
		t.Fatal("the home directory must be refused")
	}
	// /home *contains* /home/u/.ssh, so it is as unsafe as the sensitive dir.
	if err := d.ValidateMount("/home"); err == nil {
		t.Fatal("a directory containing a protected path must be refused")
	}
	if err := d.ValidateMount("/home/u/project"); err != nil {
		t.Fatalf("a normal project dir should be allowed: %v", err)
	}
}

func TestDeniedName(t *testing.T) {
	pats := []string{"auth.json", "credentials*.json", "*.pem", "*.key"}
	for _, name := range []string{"auth.json", "credentials.json", "creds.pem", "id.key"} {
		if !deniedName(name, pats) {
			t.Fatalf("%q should match the never-mount patterns", name)
		}
	}
	for _, name := range []string{"opencode.json", "agents", "settings.json"} {
		if deniedName(name, pats) {
			t.Fatalf("%q should not be denied", name)
		}
	}
}

func TestUnderAny(t *testing.T) {
	prefixes := []string{"/home/u/media/skills"}
	if !underAny("/home/u/media/skills/sub", prefixes) {
		t.Fatal("a descendant of a prefix must be under it")
	}
	if underAny("/home/u/.ssh", prefixes) {
		t.Fatal("an unrelated path must not be under the prefix")
	}
}

// --- collectSeeds branches --------------------------------------------------

type failTransform struct{}

func (failTransform) Name() string { return "boom" }
func (failTransform) Apply([]byte) ([]byte, []string, error) {
	return nil, nil, errors.New("boom")
}

func seedFS() *fsx.Fake {
	f := fsx.NewFake("/home/u", "/home/u")
	f.Mkdir("/cfg")
	return f
}

func TestCollectSeedsRequiredMissingIsFatal(t *testing.T) {
	def := agent.Definition{
		ConfigDir: "/cfg",
		SeedFiles: []agent.SeedSpec{{Rel: "required.json", Required: true}},
	}
	_, refs := collectSeeds(seedFS(), def, false)
	if len(refs) != 1 || !refs[0].Fatal {
		t.Fatalf("a missing required seed must be fatal, got %+v", refs)
	}
}

func TestCollectSeedsOptionalMissingWarns(t *testing.T) {
	def := agent.Definition{
		ConfigDir: "/cfg",
		SeedFiles: []agent.SeedSpec{{Rel: "optional.json", Required: false}},
	}
	seeds, refs := collectSeeds(seedFS(), def, false)
	if len(seeds) != 0 {
		t.Fatalf("nothing should be seeded, got %+v", seeds)
	}
	if len(refs) != 1 || refs[0].Fatal {
		t.Fatalf("a missing optional seed must warn, got %+v", refs)
	}
}

func TestCollectSeedsTransformFailureRefuses(t *testing.T) {
	f := seedFS()
	f.Write("/cfg/x.json", []byte(`{"a":1}`))
	def := agent.Definition{
		ConfigDir: "/cfg",
		SeedFiles: []agent.SeedSpec{{Rel: "x.json", Transform: failTransform{}}},
	}
	_, refs := collectSeeds(f, def, false)
	if len(refs) != 1 || !refs[0].Fatal || !strings.Contains(refs[0].Reason, "transform") {
		t.Fatalf("a transform failure must be a fatal refusal, got %+v", refs)
	}
}

func TestCollectSeedsNonJSONStrictRefuses(t *testing.T) {
	f := seedFS()
	f.Write("/cfg/x.json", []byte("this is not json"))
	def := agent.Definition{
		ConfigDir: "/cfg",
		SeedFiles: []agent.SeedSpec{{Rel: "x.json", Transform: agent.Identity{}}},
	}
	_, refs := collectSeeds(f, def, true)
	if len(refs) != 1 || !refs[0].Fatal {
		t.Fatalf("unassayable file must fail closed in strict mode, got %+v", refs)
	}
}

func TestCollectSeedsNonJSONNonStrictWarnsButSeeds(t *testing.T) {
	f := seedFS()
	f.Write("/cfg/x.json", []byte("this is not json"))
	def := agent.Definition{
		ConfigDir: "/cfg",
		SeedFiles: []agent.SeedSpec{{Rel: "x.json", Transform: agent.Identity{}}},
	}
	seeds, refs := collectSeeds(f, def, false)
	if len(seeds) != 1 {
		t.Fatalf("non-strict mode should seed with a warning, got seeds=%+v refs=%+v", seeds, refs)
	}
	if len(refs) != 1 || refs[0].Fatal {
		t.Fatalf("expected a non-fatal warning, got %+v", refs)
	}
}

func TestCollectSeedsRecordsDigestAndMode(t *testing.T) {
	f := seedFS()
	f.Write("/cfg/x.json", []byte(`{"theme":"dark"}`))
	def := agent.Definition{
		ConfigDir: "/cfg",
		SeedFiles: []agent.SeedSpec{{Rel: "x.json", Transform: agent.Identity{}}},
	}
	seeds, refs := collectSeeds(f, def, true)
	if len(refs) != 0 {
		t.Fatalf("unexpected refusals: %+v", refs)
	}
	if len(seeds) != 1 || seeds[0].SHA256 == "" || seeds[0].Mode != 0o600 {
		t.Fatalf("seed must record digest and 0600 mode: %+v", seeds)
	}
}

// --- network policy ---------------------------------------------------------

func TestDefaultEgressDecide(t *testing.T) {
	e := DefaultEgress{}
	for _, mode := range []string{"", "none", "pasta", "private", "slirp4netns", "host"} {
		d, err := e.Decide(mode)
		if err != nil {
			t.Fatalf("Decide(%q) unexpected error: %v", mode, err)
		}
		want := mode
		if want == "" {
			want = defaultNetworkMode
		}
		if d.Mode != want {
			t.Fatalf("Decide(%q).Mode = %q, want %q", mode, d.Mode, want)
		}
		if mode == "host" && d.Warning == "" {
			t.Fatal("host mode must carry a warning")
		}
	}
	if _, err := e.Decide("bridge"); err == nil {
		t.Fatal("an unknown network mode must be refused")
	}
}

func TestJoinPaths(t *testing.T) {
	if got := joinPaths([]string{"a", "b.c"}); got != "a, b.c" {
		t.Fatalf("joinPaths = %q", got)
	}
	if got := joinPaths(nil); got != "" {
		t.Fatalf("joinPaths(nil) = %q", got)
	}
}
