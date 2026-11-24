package agent

// Container-local paths. The container gets its own HOME rather than "/" —
// HOME=/ breaks agent config resolution and makes "~/..." mean the rootfs.
const (
	homeDir     = "/home/agent"
	configHome  = homeDir + "/.config"
	dataHome    = homeDir + "/.local/share"
	stateHome   = homeDir + "/.local/state"
	cacheHome   = homeDir + "/.cache"
	caBundle    = "/etc/ssl/certs/ca-certificates.crt"
	gitExecPath = "/usr/libexec/git-core"
)

// ContainerHome is the container's HOME. It is exported because the session
// mounts an ephemeral, user-owned directory there, and the rendered argv must
// agree with that decision.
const ContainerHome = homeDir

// SeedDirEnv tells the entrypoint where to copy allow-listed seed files. The
// destination is agent-specific and is not always discoverable from the
// agent's own environment (antigravity has no config-dir variable), so it is
// passed explicitly as sandbox wiring.
const SeedDirEnv = "AGENTBOX_SEED_DIR"

// baseEnv is the wiring every agent gets. With --unsetenv-all in the podman
// argv, nothing at all is inherited from the host unless it appears here or is
// explicitly requested; PATH must therefore be set rather than assumed.
func baseEnv() map[string]string {
	return map[string]string{
		"HOME":            homeDir,
		"PATH":            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG":            "C.UTF-8",
		"SSL_CERT_FILE":   caBundle,
		"GIT_SSL_CAINFO":  caBundle,
		"GIT_EXEC_PATH":   gitExecPath,
		"XDG_CONFIG_HOME": configHome,
		"XDG_DATA_HOME":   dataHome,
		"XDG_STATE_HOME":  stateHome,
		"XDG_CACHE_HOME":  cacheHome,
	}
}
