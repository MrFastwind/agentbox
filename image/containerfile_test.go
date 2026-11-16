// Package image holds the sandbox build inputs and the checks over them.
//
// embed.go compiles the Containerfiles into the binary; these tests audit the
// pins they carry and fail the build when a supply-chain guarantee is edited
// away.
package image

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The Node tarball in Containerfile.pi must be verified against a pinned
// SHA-256 before it is extracted. Fetching over TLS alone trusts the same host
// that serves the bytes, and the image is built once and then trusted for a long
// time; a pinned digest is what makes the build tamper-evident.
func TestPiContainerfilePinsNodeTarballChecksum(t *testing.T) {
	body, err := os.ReadFile("Containerfile.pi")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	digest := regexp.MustCompile(`[0-9a-f]{64}`)
	x64 := regexp.MustCompile(`(?m)^ARG NODE_SHA256_X64=([0-9a-f]{64})$`).FindStringSubmatch(src)
	arm64 := regexp.MustCompile(`(?m)^ARG NODE_SHA256_ARM64=([0-9a-f]{64})$`).FindStringSubmatch(src)
	if x64 == nil || arm64 == nil {
		t.Fatalf("Containerfile.pi must pin a per-architecture Node digest:\n%s", src)
	}
	if x64[1] == arm64[1] {
		t.Fatal("the x64 and arm64 Node digests must not be the same value")
	}
	if n := len(digest.FindAllString(src, -1)); n < 2 {
		t.Fatalf("expected at least two pinned 64-hex digests, found %d", n)
	}

	// Each architecture branch must select its own digest, and the download must
	// be checked against the selected one before extraction.
	if !strings.Contains(src, `amd64) NODE_ARCH=x64;   NODE_SHA256="$NODE_SHA256_X64"`) {
		t.Fatal("the amd64 branch must select NODE_SHA256_X64")
	}
	if !strings.Contains(src, `arm64) NODE_ARCH=arm64; NODE_SHA256="$NODE_SHA256_ARM64"`) {
		t.Fatal("the arm64 branch must select NODE_SHA256_ARM64")
	}
	if !strings.Contains(src, `"${NODE_SHA256}  node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" | sha256sum -c -`) {
		t.Fatal("the downloaded Node tarball must be verified with sha256sum -c")
	}
	for _, pkg := range []string{"xz-utils", "libatomic1"} {
		if !strings.Contains(src, pkg) {
			t.Errorf("Containerfile.pi must install %q for the Node runtime", pkg)
		}
	}

	sum := strings.Index(src, "sha256sum -c -")
	extract := strings.Index(src, "tar -xJf")
	if sum < 0 || extract < 0 || sum > extract {
		t.Fatal("the Node tarball must be verified before it is extracted")
	}
}

// The agent package tarball is pinned the same way: an exact version plus a
// digest recorded in the repository, verified before npm installs from it.
func TestPiContainerfilePinsPiTarballChecksum(t *testing.T) {
	body, err := os.ReadFile("Containerfile.pi")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	if regexp.MustCompile(`(?m)^ARG PI_SHA512_HEX=[0-9a-f]{128}$`).FindString(src) == "" {
		t.Fatalf("Containerfile.pi must pin the pi tarball SHA-512:\n%s", src)
	}
	if !strings.Contains(src, `"${PI_SHA512_HEX}  /tmp/pi.tgz" | sha512sum -c -`) {
		t.Fatal("the pi tarball must be verified with sha512sum -c")
	}
	if !strings.Contains(src, `"https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-${PI_VERSION}.tgz"`) {
		t.Fatal("the pi tarball must be fetched at the pinned exact version")
	}

	sum := strings.Index(src, "sha512sum -c -")
	install := strings.Index(src, "npm install --global --omit=dev /tmp/pi.tgz")
	if sum < 0 || install < 0 || sum > install {
		t.Fatal("the pi tarball must be verified before npm installs from it")
	}
}

// The base layer is shared by every agent image, so a package added here is
// shipped five times. Compilers, Python and an SSH client are not runtime
// dependencies of any registered agent.
func TestBaseContainerfileStaysSlim(t *testing.T) {
	body, err := os.ReadFile("Containerfile.base")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, pkg := range []string{"build-essential", "pkg-config", "python3", "openssh-client", "xz-utils", "libatomic1"} {
		if strings.Contains(src, pkg) {
			t.Errorf("Containerfile.base still installs %q", pkg)
		}
	}
	for _, pkg := range []string{"bash", "ca-certificates", "curl", "git", "jq", "less", "ripgrep", "procps"} {
		if !strings.Contains(src, "      "+pkg+" \\") {
			t.Errorf("Containerfile.base must keep %q", pkg)
		}
	}
}

// The opencode installer accepts --version; passing it is what makes the image
// reproducible. An unpinned install silently follows upstream "latest".
func TestOpencodeContainerfilePinsVersion(t *testing.T) {
	body, err := os.ReadFile("Containerfile.opencode")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	if regexp.MustCompile(`(?m)^ARG OPENCODE_VERSION=[0-9]+\.[0-9]+\.[0-9]+$`).FindString(src) == "" {
		t.Fatalf("Containerfile.opencode must pin an exact OPENCODE_VERSION:\n%s", src)
	}
	if !strings.Contains(src, `bash -s -- --version "${OPENCODE_VERSION}"`) {
		t.Fatal("the opencode installer must be given the pinned version")
	}
	if !strings.Contains(src, `opencode --version | grep -F "${OPENCODE_VERSION}"`) {
		t.Fatal("the image must fail the build when the installed version drifts")
	}
}

// The Claude Code binary must be fetched at the pinned version and checked
// against a per-architecture digest before it is installed.
func TestClaudeContainerfilePinsBinaryChecksum(t *testing.T) {
	body, err := os.ReadFile("Containerfile.claude")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	x64 := regexp.MustCompile(`(?m)^ARG CLAUDE_SHA256_X64=([0-9a-f]{64})$`).FindStringSubmatch(src)
	arm64 := regexp.MustCompile(`(?m)^ARG CLAUDE_SHA256_ARM64=([0-9a-f]{64})$`).FindStringSubmatch(src)
	if x64 == nil || arm64 == nil {
		t.Fatalf("Containerfile.claude must pin a per-architecture digest:\n%s", src)
	}
	if x64[1] == arm64[1] {
		t.Fatal("the x64 and arm64 Claude digests must not be the same value")
	}
	if !strings.Contains(src, `amd64) CLAUDE_ARCH=x64;   CLAUDE_SHA256="$CLAUDE_SHA256_X64"`) {
		t.Fatal("the amd64 branch must select CLAUDE_SHA256_X64")
	}
	if !strings.Contains(src, `arm64) CLAUDE_ARCH=arm64; CLAUDE_SHA256="$CLAUDE_SHA256_ARM64"`) {
		t.Fatal("the arm64 branch must select CLAUDE_SHA256_ARM64")
	}
	if !strings.Contains(src, `"https://downloads.claude.ai/claude-code-releases/${CLAUDE_VERSION}/linux-${CLAUDE_ARCH}/claude"`) {
		t.Fatal("the binary must be fetched at the pinned exact version")
	}
	if !strings.Contains(src, `"${CLAUDE_SHA256}  /tmp/claude" | sha256sum -c -`) {
		t.Fatal("the downloaded binary must be verified with sha256sum -c")
	}

	sum := strings.Index(src, "sha256sum -c -")
	install := strings.Index(src, "/tmp/claude install")
	if sum < 0 || install < 0 || sum > install {
		t.Fatal("the Claude binary must be verified before it is installed")
	}
	if !strings.Contains(src, "ENV DISABLE_AUTOUPDATER=1") {
		t.Fatal("the image must disable Claude's background auto-updater")
	}
	if !strings.Contains(src, `claude --version | grep -F "${CLAUDE_VERSION}"`) {
		t.Fatal("the image must fail the build when the installed version drifts")
	}
}

// The Antigravity installer cannot pin a version, so the release tarball is the
// only reproducible path. It must be digest-checked before extraction.
func TestAntigravityContainerfilePinsTarballChecksum(t *testing.T) {
	body, err := os.ReadFile("Containerfile.antigravity")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	x64 := regexp.MustCompile(`(?m)^ARG AGY_SHA256_X64=([0-9a-f]{64})$`).FindStringSubmatch(src)
	arm64 := regexp.MustCompile(`(?m)^ARG AGY_SHA256_ARM64=([0-9a-f]{64})$`).FindStringSubmatch(src)
	if x64 == nil || arm64 == nil {
		t.Fatalf("Containerfile.antigravity must pin a per-architecture digest:\n%s", src)
	}
	if x64[1] == arm64[1] {
		t.Fatal("the x64 and arm64 Antigravity digests must not be the same value")
	}
	if !strings.Contains(src, `amd64) AGY_ARCH=x64;   AGY_SHA256="$AGY_SHA256_X64"`) {
		t.Fatal("the amd64 branch must select AGY_SHA256_X64")
	}
	if !strings.Contains(src, `arm64) AGY_ARCH=arm64; AGY_SHA256="$AGY_SHA256_ARM64"`) {
		t.Fatal("the arm64 branch must select AGY_SHA256_ARM64")
	}
	if !strings.Contains(src, `"https://github.com/google-antigravity/antigravity-cli/releases/download/${AGY_VERSION}/agy_cli_linux_${AGY_ARCH}.tar.gz"`) {
		t.Fatal("the tarball must be fetched from the pinned exact release")
	}
	if !strings.Contains(src, `"${AGY_SHA256}  /tmp/agy.tar.gz" | sha256sum -c -`) {
		t.Fatal("the downloaded tarball must be verified with sha256sum -c")
	}

	sum := strings.Index(src, "sha256sum -c -")
	extract := strings.Index(src, "tar -xzf")
	if sum < 0 || extract < 0 || sum > extract {
		t.Fatal("the Antigravity tarball must be verified before it is extracted")
	}
	if !strings.Contains(src, `agy --version | grep -F "${AGY_VERSION}"`) {
		t.Fatal("the image must fail the build when the installed version drifts")
	}
}
