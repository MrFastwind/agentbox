// Package image carries the sandbox build inputs.
//
// The Containerfiles and the entrypoint are compiled into the agentbox binary,
// so a lone downloaded executable can build its own images; the on-disk copies
// stay because they are the reviewable artifact and containerfile_test.go
// audits the pins they are supposed to carry. internal/podman/seccomp.go
// embeds its profile the same way for the same reason: the binary is the
// distribution unit.
package image

import "embed"

// FS holds every input `agentbox images build` needs. The list is explicit
// rather than "Containerfile.*": adding a target must be a deliberate edit
// here, because this set — not whatever happens to be in a directory beside the
// executable — is what the shipped binary will build.
//
//go:embed Containerfile.base Containerfile.opencode Containerfile.pi Containerfile.claude Containerfile.antigravity entrypoint.sh pins.yaml
var FS embed.FS
