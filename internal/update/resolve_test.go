package update

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func testResolver(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *Resolver {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return &Resolver{
		Client:      server.Client(),
		GitHubAPI:   server.URL,
		NPMRegistry: server.URL,
		Now:         func() time.Time { return fixedTime },
	}
}

func serveJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func releaseJSON(tag string, assets ...githubAsset) []githubRelease {
	return []githubRelease{{TagName: tag, HTMLURL: "https://example.test/release", Assets: assets}}
}

func currentAgentArgs() map[string]string {
	return map[string]string{
		"DEBIAN_IMAGE":      "docker.io/library/debian:stable-slim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"NODE_VERSION":      "26.13.1",
		"NODE_SHA256_X64":   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"NODE_SHA256_ARM64": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
}

func TestResolveOpencodeUsesNewestStableRelease(t *testing.T) {
	sums := "1111111111111111111111111111111111111111111111111111111111111111  opencode-linux-x64.tar.gz\n" +
		"2222222222222222222222222222222222222222222222222222222222222222  opencode-linux-arm64.tar.gz\n"
	var resolver *Resolver
	resolver = testResolver(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/repos/anomalyco/opencode/releases"):
			serveJSON(t, w, []githubRelease{
				{TagName: "v9.9.9-beta.1", Prerelease: true},
				{TagName: "v1.19.6", HTMLURL: "https://example.test/old"},
				{TagName: "v2.4.1", HTMLURL: "https://example.test/new", Assets: []githubAsset{
					{Name: "SHA256SUMS", BrowserDownloadURL: resolver.GitHubAPI + "/sums"},
				}},
			})
		case r.URL.Path == "/sums":
			fmt.Fprint(w, sums)
		default:
			http.NotFound(w, r)
		}
	})
	pin, err := resolver.Resolve(context.Background(), "opencode", AgentPin{Args: currentAgentArgs()})
	if err != nil {
		t.Fatal(err)
	}
	if pin.Version != "2.4.1" || pin.Args["OPENCODE_VERSION"] != "2.4.1" {
		t.Fatalf("pin = %+v", pin)
	}
	if pin.Args["OPENCODE_SHA256_X64"] != strings.Repeat("1", 64) || pin.Args["OPENCODE_SHA256_ARM64"] != strings.Repeat("2", 64) {
		t.Fatalf("checksums = %+v", pin.Args)
	}
	if pin.Source != "https://example.test/new" || pin.ResolvedAt != fixedTime.Format(time.RFC3339) {
		t.Fatalf("source/time = %q/%q", pin.Source, pin.ResolvedAt)
	}
}

func TestResolveClaudeUsesReleaseChecksums(t *testing.T) {
	sums := "3333333333333333333333333333333333333333333333333333333333333333  claude-linux-x64.tar.gz\n" +
		"4444444444444444444444444444444444444444444444444444444444444444  claude-linux-arm64.tar.gz\n"
	var resolver *Resolver
	resolver = testResolver(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/repos/anthropics/claude-code/releases"):
			serveJSON(t, w, releaseJSON("v2.1.331", githubAsset{Name: "SHASUMS256.txt", BrowserDownloadURL: resolver.GitHubAPI + "/sums"}))
		case r.URL.Path == "/sums":
			fmt.Fprint(w, sums)
		default:
			http.NotFound(w, r)
		}
	})
	pin, err := resolver.Resolve(context.Background(), "claude", AgentPin{Args: currentAgentArgs()})
	if err != nil {
		t.Fatal(err)
	}
	if pin.Version != "2.1.331" || pin.Args["CLAUDE_SHA256_X64"] != strings.Repeat("3", 64) {
		t.Fatalf("pin = %+v", pin)
	}
}

func TestResolveAntigravityUsesAssetDigest(t *testing.T) {
	resolver := testResolver(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/google-antigravity/cli/releases") {
			http.NotFound(w, r)
			return
		}
		serveJSON(t, w, releaseJSON("1.5.16",
			githubAsset{Name: "agy_cli_linux_x64.tar.gz", Digest: "sha256:" + strings.Repeat("5", 64)},
			githubAsset{Name: "agy_cli_linux_arm64.tar.gz", Digest: "sha256:" + strings.Repeat("6", 64)},
		))
	})
	pin, err := resolver.Resolve(context.Background(), "antigravity", AgentPin{Args: currentAgentArgs()})
	if err != nil {
		t.Fatal(err)
	}
	if pin.Version != "1.5.16" || pin.Args["AGY_SHA256_X64"] != strings.Repeat("5", 64) {
		t.Fatalf("pin = %+v", pin)
	}
}

func TestResolvePiUsesRegistryIntegrity(t *testing.T) {
	integrity := "sha512-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 64)))
	resolver := testResolver(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.EscapedPath(), "pi-coding-agent") {
			http.NotFound(w, r)
			return
		}
		var pkg npmPackage
		pkg.DistTags.Latest = "1.6.0"
		pkg.Versions = map[string]npmVersion{
			"1.6.0": {
				Dist: struct {
					Integrity string `json:"integrity"`
				}{Integrity: integrity},
				Engines: map[string]string{"node": ">=22.19.0"},
			},
		}
		serveJSON(t, w, pkg)
	})
	pin, err := resolver.Resolve(context.Background(), "pi", AgentPin{Args: currentAgentArgs()})
	if err != nil {
		t.Fatal(err)
	}
	if pin.Version != "1.6.0" || pin.Args["PI_SHA512_HEX"] != strings.Repeat("61", 64) {
		t.Fatalf("pin = %+v", pin)
	}
	if pin.Args["NODE_VERSION"] != "26.13.1" {
		t.Fatal("pi resolution dropped the current Node pin")
	}
}

func TestResolveRejectsMalformedUpstream(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{
			name:   "unknown target",
			target: "shell",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "unknown", http.StatusNotFound)
			},
		},
		{
			name:   "no stable release",
			target: "claude",
			handler: func(w http.ResponseWriter, r *http.Request) {
				serveJSON(t, w, []githubRelease{{TagName: "v9.9.9-beta", Prerelease: true}})
			},
		},
		{
			name:   "release list status",
			target: "opencode",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", http.StatusBadGateway)
			},
		},
		{
			name:   "missing checksum asset",
			target: "claude",
			handler: func(w http.ResponseWriter, r *http.Request) {
				serveJSON(t, w, releaseJSON("v2.1.331"))
			},
		},
		{
			name:   "checksum status",
			target: "opencode",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/repos/") {
					serveJSON(t, w, releaseJSON("v2.4.1", githubAsset{Name: "SHA256SUMS", BrowserDownloadURL: "http://127.0.0.1:1/sums"}))
					return
				}
				http.Error(w, "boom", http.StatusBadGateway)
			},
		},
		{
			name:   "missing asset digest",
			target: "antigravity",
			handler: func(w http.ResponseWriter, r *http.Request) {
				serveJSON(t, w, releaseJSON("1.5.16", githubAsset{Name: "unrelated", Digest: "sha256:" + strings.Repeat("7", 64)}))
			},
		},
		{
			name:   "pi status",
			target: "pi",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", http.StatusBadGateway)
			},
		},
		{
			name:   "pi unstable tag",
			target: "pi",
			handler: func(w http.ResponseWriter, r *http.Request) {
				var pkg npmPackage
				pkg.DistTags.Latest = "1.6.0-beta.1"
				serveJSON(t, w, pkg)
			},
		},
		{
			name:   "pi missing integrity",
			target: "pi",
			handler: func(w http.ResponseWriter, r *http.Request) {
				var pkg npmPackage
				pkg.DistTags.Latest = "1.6.0"
				serveJSON(t, w, pkg)
			},
		},
		{
			name:   "pi bad integrity",
			target: "pi",
			handler: func(w http.ResponseWriter, r *http.Request) {
				var pkg npmPackage
				pkg.DistTags.Latest = "1.6.0"
				pkg.Versions = map[string]npmVersion{"1.6.0": {Dist: struct {
					Integrity string `json:"integrity"`
				}{Integrity: "md5-deadbeef"}}}
				serveJSON(t, w, pkg)
			},
		},
		{
			name:   "pi node too old",
			target: "pi",
			handler: func(w http.ResponseWriter, r *http.Request) {
				var pkg npmPackage
				pkg.DistTags.Latest = "1.6.0"
				pkg.Versions = map[string]npmVersion{"1.6.0": {
					Dist: struct {
						Integrity string `json:"integrity"`
					}{Integrity: "sha512-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 64)))},
					Engines: map[string]string{"node": ">=99.0.0"},
				}}
				serveJSON(t, w, pkg)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver := testResolver(t, tc.handler)
			if _, err := resolver.Resolve(context.Background(), tc.target, AgentPin{Args: currentAgentArgs()}); err == nil {
				t.Fatal("Resolve accepted malformed upstream metadata")
			}
		})
	}
}

func TestResolveRejectsMissingClientAndArgs(t *testing.T) {
	if _, err := (&Resolver{}).Resolve(context.Background(), "opencode", AgentPin{}); err == nil {
		t.Fatal("Resolve accepted a nil http client")
	}
	resolver := testResolver(t, func(w http.ResponseWriter, r *http.Request) {
		var pkg npmPackage
		pkg.DistTags.Latest = "1.6.0"
		pkg.Versions = map[string]npmVersion{"1.6.0": {Dist: struct {
			Integrity string `json:"integrity"`
		}{Integrity: "sha512-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 64)))}}}
		serveJSON(t, w, pkg)
	})
	if _, err := resolver.Resolve(context.Background(), "pi", AgentPin{}); err == nil {
		t.Fatal("Resolve accepted missing node args")
	}
	args := currentAgentArgs()
	delete(args, "NODE_SHA256_ARM64")
	if _, err := resolver.Resolve(context.Background(), "pi", AgentPin{Args: args}); err == nil {
		t.Fatal("Resolve accepted a partial node pin")
	}
}

func TestParseChecksumsRejectsBadDigests(t *testing.T) {
	if _, err := parseChecksums("not a checksum line"); err == nil {
		t.Fatal("parseChecksums accepted an empty file")
	}
	if _, err := parseChecksums("xyz  opencode-linux-x64.tar.gz"); err == nil {
		t.Fatal("parseChecksums accepted a bad digest")
	}
}

func TestIntegrityToHexRejectsMalformedValues(t *testing.T) {
	for _, integrity := range []string{"sha256-abc", "sha512-%%%", "sha512-YWJj"} {
		if _, err := integrityToHex(integrity); err == nil {
			t.Errorf("integrityToHex accepted %q", integrity)
		}
	}
	if got, err := integrityToHex("sha512-" + base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("b", 64)))); err != nil || got != strings.Repeat("62", 64) {
		t.Fatalf("integrityToHex = (%q, %v)", got, err)
	}
}
