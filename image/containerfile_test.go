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

	"agentbox/internal/update"
)

var argWithDefault = regexp.MustCompile(`(?m)^ARG [A-Z0-9_]+=`)
var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func readContainerfile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func loadPinsForTest(t *testing.T) update.PinSet {
	t.Helper()
	pins, err := update.LoadPins(FS, "pins.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

func requireBuildArgs(t *testing.T, src string, names ...string) {
	t.Helper()
	for _, match := range argWithDefault.FindAllString(src, -1) {
		if !strings.HasPrefix(match, "ARG BASE=") {
			t.Fatalf("Containerfile has a floating ARG default: %s", match)
		}
	}
	for _, name := range names {
		if !regexp.MustCompile(`(?m)^ARG ` + name + `$`).MatchString(src) {
			t.Errorf("Containerfile must require %s as a build arg", name)
		}
	}
}

func requirePins(t *testing.T, args map[string]string, names ...string) {
	t.Helper()
	for _, name := range names {
		value := args[name]
		if value == "" {
			t.Errorf("pins.yaml is missing %s", name)
			continue
		}
		if strings.Contains(name, "SHA") && name != "PI_SHA512_HEX" && !hexDigest.MatchString(value) {
			t.Errorf("pins.yaml %s is not a sha256 digest", name)
		}
		if name == "PI_SHA512_HEX" && len(value) != 128 {
			t.Errorf("pins.yaml %s is not a sha512 digest", name)
		}
	}
}

func checksumBefore(t *testing.T, src, checksum, action string) {
	t.Helper()
	sum, use := strings.Index(src, checksum), strings.Index(src, action)
	if sum < 0 || use < 0 || sum > use {
		t.Fatalf("%s must be verified with %s before %s", checksum, checksum, action)
	}
}

// Versions and digests live in pins.yaml; Containerfiles must take them as
// mandatory build args so a binary cannot silently build from stale defaults.
func TestBaseContainerfileUsesReviewedPins(t *testing.T) {
	src := readContainerfile(t, "Containerfile.base")
	requireBuildArgs(t, src, "ALPINE_IMAGE")
	pins := loadPinsForTest(t)
	requirePins(t, pins.Base.Args, "ALPINE_IMAGE")
	if ref := pins.Base.Args["ALPINE_IMAGE"]; !strings.Contains(ref, "@sha256:") {
		t.Errorf("base image %q is not pinned by digest", ref)
	}
	if !strings.Contains(src, "FROM ${ALPINE_IMAGE} AS tools") || !strings.Contains(src, "FROM scratch") {
		t.Fatal("base stages must come from the reviewed Alpine arg and end in scratch")
	}
	for _, stale := range []string{"DEBIAN_IMAGE", "DISTROLESS_IMAGE", "apt-get", "build-essential", "pkg-config", "python3", "openssh-client", "xz-utils", "libatomic1"} {
		if strings.Contains(src, stale) {
			t.Errorf("Containerfile.base still carries Debian-era %q", stale)
		}
	}
	for _, pkg := range []string{"bash", "ca-certificates", "curl", "git", "jq", "less", "musl-utils", "ncurses-terminfo-base", "procps-ng", "ripgrep"} {
		if !strings.Contains(src, "      "+pkg+" \\") {
			t.Errorf("Containerfile.base must keep %q", pkg)
		}
	}
	if !strings.Contains(src, "cp -a /usr/lib/git-core/. /out/usr/libexec/git-core/") {
		t.Fatal("git helpers must be copied under the GIT_EXEC_PATH used by policy")
	}
}

func TestPiContainerfileVerifiesPinnedTarballs(t *testing.T) {
	src := readContainerfile(t, "Containerfile.pi")
	requireBuildArgs(t, src, "ALPINE_IMAGE", "NODE_VERSION", "NODE_SHA256_X64", "NODE_SHA256_ARM64", "PI_VERSION", "PI_SHA512_HEX")
	args := loadPinsForTest(t).Agents["pi"].Args
	requirePins(t, args, "ALPINE_IMAGE", "NODE_VERSION", "NODE_SHA256_X64", "NODE_SHA256_ARM64", "PI_VERSION", "PI_SHA512_HEX")
	if !strings.Contains(src, `amd64) NODE_ARCH=x64;   NODE_HOST=https://nodejs.org/dist; NODE_SHA256="$NODE_SHA256_X64"`) {
		t.Fatal("the amd64 branch must select the official x64 musl Node tarball")
	}
	if !strings.Contains(src, `arm64) NODE_ARCH=arm64; NODE_HOST=https://unofficial-builds.nodejs.org/download/release; NODE_SHA256="$NODE_SHA256_ARM64"`) {
		t.Fatal("the arm64 branch must select the arm64 musl Node tarball")
	}
	if !strings.Contains(src, `${NODE_HOST}/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}-musl.tar.xz`) {
		t.Fatal("Node must be fetched as a pinned musl tarball")
	}
	checksumBefore(t, src, "sha256sum -c -", "tar -xJf")
	if !strings.Contains(src, `"${PI_SHA512_HEX}  /tmp/pi.tgz" | sha512sum -c -`) {
		t.Fatal("the pi tarball must be verified with sha512sum -c")
	}
	if !strings.Contains(src, `"https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-${PI_VERSION}.tgz"`) {
		t.Fatal("the pi tarball must be fetched at the pinned exact version")
	}
	checksumBefore(t, src, "sha512sum -c -", "npm install --global --omit=dev /tmp/pi.tgz")
	for _, pkg := range []string{"libgcc", "libstdc++", "musl-utils", "tar", "xz"} {
		continued := "      " + pkg + " \\\n"
		final := "      " + pkg + "\n"
		if !strings.Contains(src, continued) && !strings.Contains(src, final) {
			t.Errorf("Containerfile.pi must install %q for the Node musl runtime", pkg)
		}
	}
	for _, stale := range []string{"DEBIAN_IMAGE", "apt-get", "libatomic1", "linux-${NODE_ARCH}.tar.xz"} {
		if strings.Contains(src, stale) {
			t.Errorf("Containerfile.pi still carries Debian-era %q", stale)
		}
	}
}

func TestOpencodeContainerfileVerifiesPinnedTarball(t *testing.T) {
	src := readContainerfile(t, "Containerfile.opencode")
	requireBuildArgs(t, src, "OPENCODE_VERSION", "OPENCODE_SHA256_X64", "OPENCODE_SHA256_ARM64")
	args := loadPinsForTest(t).Agents["opencode"].Args
	requirePins(t, args, "OPENCODE_VERSION", "OPENCODE_SHA256_X64", "OPENCODE_SHA256_ARM64")
	if strings.Contains(src, "curl -fsSL https://opencode.ai/install | bash") {
		t.Fatal("the floating vendor installer must not be used")
	}
	if !strings.Contains(src, `"https://github.com/anomalyco/opencode/releases/download/v${OPENCODE_VERSION}/opencode-linux-${ARCH}-musl.tar.gz"`) {
		t.Fatal("the musl tarball must be fetched from the pinned exact release")
	}
	if !strings.Contains(src, `printf '%s  %s\n' "${SUM}" /tmp/opencode.tar.gz | sha256sum -c -`) {
		t.Fatal("the tarball must be verified with sha256sum -c")
	}
	checksumBefore(t, src, "sha256sum -c -", "tar -xzf")
	if !strings.Contains(src, `opencode --version | grep -F "${OPENCODE_VERSION}"`) {
		t.Fatal("the image must fail the build when the installed version drifts")
	}
}

func TestClaudeContainerfileVerifiesPinnedTarball(t *testing.T) {
	src := readContainerfile(t, "Containerfile.claude")
	requireBuildArgs(t, src, "CLAUDE_VERSION", "CLAUDE_SHA256_X64", "CLAUDE_SHA256_ARM64")
	args := loadPinsForTest(t).Agents["claude"].Args
	requirePins(t, args, "CLAUDE_VERSION", "CLAUDE_SHA256_X64", "CLAUDE_SHA256_ARM64")
	if !strings.Contains(src, `"https://github.com/anthropics/claude-code/releases/download/v${CLAUDE_VERSION}/claude-linux-${ARCH}-musl.tar.gz"`) {
		t.Fatal("the musl tarball must be fetched from the pinned exact release")
	}
	if !strings.Contains(src, `printf '%s  %s\n' "${SUM}" /tmp/claude.tar.gz | sha256sum -c -`) {
		t.Fatal("the tarball must be verified with sha256sum -c")
	}
	checksumBefore(t, src, "sha256sum -c -", "tar -xzf")
	if strings.Contains(src, "ENV DISABLE_AUTOUPDATER=1") {
		t.Fatal("--unsetenv-all strips image ENV; auto-update wiring belongs in agent policy")
	}
	if !strings.Contains(src, `claude --version | grep -F "${CLAUDE_VERSION}"`) {
		t.Fatal("the image must fail the build when the installed version drifts")
	}
}

func TestAntigravityContainerfileVerifiesPinnedTarball(t *testing.T) {
	src := readContainerfile(t, "Containerfile.antigravity")
	requireBuildArgs(t, src, "AGY_VERSION", "AGY_SHA256_X64", "AGY_SHA256_ARM64")
	args := loadPinsForTest(t).Agents["antigravity"].Args
	requirePins(t, args, "AGY_VERSION", "AGY_SHA256_X64", "AGY_SHA256_ARM64")
	if regexp.MustCompile(`(?m)^\s*curl .*install\.sh`).MatchString(src) {
		t.Fatal("the floating vendor installer must not be used")
	}
	if !strings.Contains(src, `"https://github.com/google-antigravity/antigravity-cli/releases/download/${AGY_VERSION}/agy_cli_linux_${AGY_ARCH}_musl.tar.gz"`) {
		t.Fatal("the musl tarball must be fetched from the pinned exact release")
	}
	if !strings.Contains(src, `"${AGY_SHA256}  /tmp/agy.tar.gz" | sha256sum -c -`) {
		t.Fatal("the tarball must be verified with sha256sum -c")
	}
	checksumBefore(t, src, "sha256sum -c -", "tar -xzf")
	if !strings.Contains(src, `agy --version | grep -F "${AGY_VERSION}"`) {
		t.Fatal("the image must fail the build when the installed version drifts")
	}
}
