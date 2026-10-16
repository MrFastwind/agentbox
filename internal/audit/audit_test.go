package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"agentbox/internal/policy"
)

// TestRedactArgvValuesNeverSurvive is the single most important audit test: a
// crossed credential is a capability, and it must never reach the on-disk log.
func TestRedactArgvValuesNeverSurvive(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{
			name: "secret value is replaced, name kept",
			argv: []string{"run", "--env", "ANTHROPIC_API_KEY=sk-live-123", "--rm", "img"},
			want: []string{"run", "--env", "ANTHROPIC_API_KEY=***", "--rm", "img"},
		},
		{
			name: "every env pair is redacted, not just credential-shaped names",
			argv: []string{"--env", "HOME=/home/agent", "--env", "PATH=/usr/bin"},
			want: []string{"--env", "HOME=***", "--env", "PATH=***"},
		},
		{
			name: "empty value still redacted",
			argv: []string{"--env", "NAME="},
			want: []string{"--env", "NAME=***"},
		},
		{
			name: "value with no equals is left intact (podman -e NAME would copy host)",
			argv: []string{"--env", "JUSTANAME"},
			want: []string{"--env", "JUSTANAME"},
		},
		{
			name: "trailing --env with no value does not panic or truncate",
			argv: []string{"run", "--env"},
			want: []string{"run", "--env"},
		},
		{
			name: "non-env tokens are untouched",
			argv: []string{"run", "--volume", "/a:/b:ro", "--network", "none"},
			want: []string{"run", "--volume", "/a:/b:ro", "--network", "none"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := append([]string(nil), tc.argv...)
			got := RedactArgv(in)
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("RedactArgv(%q) = %q, want %q", tc.argv, got, tc.want)
			}
			// The input slice must not be mutated in place.
			if strings.Join(in, "\x00") != strings.Join(tc.argv, "\x00") {
				t.Fatalf("RedactArgv mutated its input: %q", in)
			}
		})
	}
}

func sampleSpec() *policy.ResolvedSpec {
	return &policy.ResolvedSpec{
		Agent:      "pi",
		Image:      "localhost/agentbox/pi:latest",
		UserConfig: true,
		Network:    policy.NetworkDecision{Mode: "pasta", Warning: "pasta note"},
		Userns:     "keep-id",
		CapDrop:    true,
		ReadOnly:   true,
		UnsetEnv:   true,
		HTTPProxy:  false,
		Limits:     policy.Limits{Memory: "4g", CPUs: "2", Pids: 2048},
		Tmpfs:      []string{"/tmp"},
		Mounts: []policy.ResolvedMount{
			{Host: "/work", Dest: "/workspace", Access: policy.RW, Origin: "launch-dir"},
			{Host: "/home/u/.config/opencode", Dest: "/home/agent/.config/opencode", Access: policy.RO, Origin: "agent-config"},
		},
		Env: []policy.EnvPair{
			{Name: "PI_CODING_AGENT_DIR", Value: "/home/agent/.config/pi"},
			{Name: "ANTHROPIC_API_KEY", Value: "sk-live-TOPSECRET"},
		},
		Seed: []policy.SeededFile{
			{Rel: "settings.json", Size: 12, SHA256: "deadbeef", Transform: "StripCredentialKeys", RemovedKeys: []string{"apiKeys"}},
		},
		WritableStateDirs: []string{"/home/agent"},
		Refusals: []policy.Refusal{
			{Kind: policy.RefusalSeed, Subject: "x", Reason: "r", Fatal: false},
		},
	}
}

func TestRecordRedactsSecretsAndKeepsNames(t *testing.T) {
	spec := sampleSpec()
	argv := []string{
		"run", "--rm",
		"--env", "ANTHROPIC_API_KEY=sk-live-TOPSECRET",
		"--env", "PI_CODING_AGENT_DIR=/home/agent/.config/pi",
		"--volume", "/work:/workspace:rw",
		"localhost/agentbox/pi:latest",
	}

	var buf bytes.Buffer
	if err := New(&buf).Record(spec, argv); err != nil {
		t.Fatalf("Record: %v", err)
	}
	raw := buf.String()

	if strings.Contains(raw, "sk-live-TOPSECRET") {
		t.Fatalf("secret value leaked into audit record:\n%s", raw)
	}
	if !strings.Contains(raw, "ANTHROPIC_API_KEY") {
		t.Fatalf("env name missing from audit record:\n%s", raw)
	}

	var rec Record
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("record is not valid JSON: %v", err)
	}

	// Env names are recorded (sorted), values never are.
	wantNames := []string{"ANTHROPIC_API_KEY", "PI_CODING_AGENT_DIR"}
	if strings.Join(rec.EnvNames, ",") != strings.Join(wantNames, ",") {
		t.Fatalf("EnvNames = %v, want %v", rec.EnvNames, wantNames)
	}

	// The argv stored in the record is the redacted one.
	for _, a := range rec.Argv {
		if strings.Contains(a, "TOPSECRET") {
			t.Fatalf("redacted argv still holds a secret: %q", a)
		}
	}

	// Structural facts are carried through.
	if rec.Agent != "pi" || rec.Network != "pasta" || rec.NetworkNote != "pasta note" {
		t.Fatalf("agent/network not recorded: %+v", rec)
	}
	if len(rec.Mounts) != 2 {
		t.Fatalf("want 2 mounts recorded, got %d", len(rec.Mounts))
	}
	if rec.Mounts[0].Access != "rw" || rec.Mounts[1].Access != "ro" {
		t.Fatalf("mount access not recorded: %+v", rec.Mounts)
	}
	if len(rec.Seeded) != 1 || rec.Seeded[0].SHA256 != "deadbeef" {
		t.Fatalf("seeded files not recorded: %+v", rec.Seeded)
	}
	if rec.Seeded[0].RemovedKeys == nil || len(rec.Seeded[0].RemovedKeys) != 1 {
		t.Fatalf("removed keys not recorded: %+v", rec.Seeded[0])
	}
	if len(rec.Refusals) != 1 || !strings.Contains(rec.Refusals[0], "seed") {
		t.Fatalf("refusals not recorded: %+v", rec.Refusals)
	}
	if rec.Limits.Pids != 2048 || rec.Limits.Memory != "4g" {
		t.Fatalf("limits not recorded: %+v", rec.Limits)
	}
}

func TestNewReturnsUsableLogger(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	if l == nil {
		t.Fatal("New returned nil")
	}
	if err := l.Record(sampleSpec(), []string{"run", "img"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("Record wrote nothing")
	}
}
