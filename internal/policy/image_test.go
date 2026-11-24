package policy_test

import (
	"strings"
	"testing"

	"agentbox/internal/agent"
	"agentbox/internal/policy"
)

func TestValidateImageRefAcceptsFullyQualifiedNames(t *testing.T) {
	for _, ref := range []string{
		"localhost/agentbox/opencode:latest",
		"localhost/agentbox/base:latest",
		"docker.io/library/debian:stable-slim",
		"docker.io/openeuler/opencode:1.18.30-oe2403sp4",
		"registry.example.com:5000/team/agent:v1",
		"docker.io/library/debian@sha256:0000000000000000000000000000000000000000000000000000000000000000",
	} {
		if err := policy.ValidateImageRef(ref); err != nil {
			t.Errorf("expected %q to be accepted, got %v", ref, err)
		}
	}
}

func TestValidateImageRefRejectsUnqualifiedNames(t *testing.T) {
	// These are the references that resolve differently per host: under Docker
	// they mean docker.io/..., under podman they depend on the search list.
	for _, ref := range []string{
		"",
		"opencode",
		"ubuntu",
		"agentbox/opencode:latest",
		"agentbox/base:latest",
		"library/debian:stable-slim",
		"openeuler/opencode:latest",
		"docker.io/library/debian:stable-slim extra",
		"https://docker.io/openeuler/opencode",
		"localhost",
		"/agentbox/opencode",
		"docker.io/library/debian@sha512:deadbeef",
	} {
		if err := policy.ValidateImageRef(ref); err == nil {
			t.Errorf("expected %q to be refused", ref)
		}
	}
}

func TestRegistryDefaultsAreFullyQualified(t *testing.T) {
	// The built-in references must survive the same check applied to overrides,
	// or the tool could ship the very ambiguity it refuses from users.
	for _, ref := range []string{
		agent.DefaultImage("base"),
		agent.DefaultImage("opencode"),
		agent.DefaultImage("pi"),
	} {
		if err := policy.ValidateImageRef(ref); err != nil {
			t.Errorf("built-in reference %q is not fully qualified: %v", ref, err)
		}
	}
}

func TestUnqualifiedImageOverrideRefused(t *testing.T) {
	_, err := resolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir: testHome + "/project",
		Image:     "agentbox/opencode:latest",
	}, nil)
	rerr := wantRefusal(t, err)
	if rerr.Refusals[0].Kind != policy.RefusalImage {
		t.Errorf("expected a %q refusal, got %q", policy.RefusalImage, rerr.Refusals[0].Kind)
	}
}

func TestQualifiedImageOverrideAccepted(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir: testHome + "/project",
		Image:     "docker.io/openeuler/opencode:1.18.30-oe2403sp4",
	})
	if spec.Image != "docker.io/openeuler/opencode:1.18.30-oe2403sp4" {
		t.Errorf("override not applied: %s", spec.Image)
	}
}

func TestDefaultImageIsFullyQualified(t *testing.T) {
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{LaunchDir: testHome + "/project"})
	if err := policy.ValidateImageRef(spec.Image); err != nil {
		t.Errorf("default image %q is not fully qualified: %v", spec.Image, err)
	}
}

func TestInstalledImageMetadataIsValidated(t *testing.T) {
	for _, version := range []string{"2.4.1", "v1.5.16"} {
		if err := policy.ValidateAgentVersion(version); err != nil {
			t.Errorf("ValidateAgentVersion(%q) = %v", version, err)
		}
	}
	for _, version := range []string{"", "latest", "1.2", "1.2.3-beta", "1.2.3.4"} {
		if err := policy.ValidateAgentVersion(version); err == nil {
			t.Errorf("ValidateAgentVersion accepted %q", version)
		}
	}
	good := "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := policy.ValidateImageDigest(good); err != nil {
		t.Errorf("ValidateImageDigest = %v", err)
	}
	for _, digest := range []string{"", "deadbeef", "sha512:" + strings.Repeat("a", 128)} {
		if err := policy.ValidateImageDigest(digest); err == nil {
			t.Errorf("ValidateImageDigest accepted %q", digest)
		}
	}
}

func TestResolveRejectsMalformedInstalledMetadata(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  policy.Request
	}{
		{"version", policy.Request{LaunchDir: testHome + "/project", ImageVersion: "latest"}},
		{"digest", policy.Request{LaunchDir: testHome + "/project", ImageDigest: "deadbeef"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolve(t, opencodeHost(), "opencode", tc.req, nil)
			rerr := wantRefusal(t, err)
			if rerr.Refusals[0].Kind != policy.RefusalImage {
				t.Errorf("expected a %q refusal, got %q", policy.RefusalImage, rerr.Refusals[0].Kind)
			}
		})
	}
}

func TestResolveCarriesValidInstalledMetadata(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	spec := mustResolve(t, opencodeHost(), "opencode", policy.Request{
		LaunchDir:    testHome + "/project",
		ImageVersion: "2.4.1",
		ImageDigest:  digest,
	})
	if spec.ImageVersion != "2.4.1" || spec.ImageDigest != digest {
		t.Fatalf("metadata = %q/%q", spec.ImageVersion, spec.ImageDigest)
	}
}
