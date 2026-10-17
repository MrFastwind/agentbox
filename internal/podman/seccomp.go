package podman

import _ "embed"

// SeccompProfileName is the base name used when the profile is staged for
// podman to read.
const SeccompProfileName = "agentbox-seccomp.json"

// seccompProfile is the seccomp policy every run installs.
//
// It is allow-by-default and removes only the syscalls that create nested user
// namespaces:
//
//   - unshare(2) is denied outright;
//   - clone(2) is denied when CLONE_NEWUSER (0x10000000) is set;
//   - clone3(2) is denied with ENOSYS, so callers fall back to clone(2), where
//     the CLONE_NEWUSER argument can actually be inspected.
//
// The point is defence in depth for a rootless run whose own userns maps the
// invoking user: without this, an agent that exploits the kernel could create a
// further user namespace and gain a fresh, fully-privileged capability set
// inside it. Removing only these calls keeps ordinary operation — including
// threaded runtimes and TUIs — working, because the default action stays ALLOW.
//
// Residual: the kernel's namespaces are not the only escape surface, and this
// profile is not a substitute for keeping the host kernel patched.
//
//go:embed seccomp-nested-userns.json
var seccompProfile []byte

// SeccompProfile returns the JSON bytes of the profile above.
func SeccompProfile() []byte { return seccompProfile }
