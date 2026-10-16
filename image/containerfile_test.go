// Package image holds checks over the sandbox Containerfiles.
//
// It has no non-test files: the Containerfiles are the artifact, and these tests
// fail the build when a supply-chain guarantee they are supposed to carry is
// edited away.
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
