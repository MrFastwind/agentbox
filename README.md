# agentbox

Run a coding agent (opencode, pi, claude, antigravity) inside a rootless-podman
sandbox that is deliberately small, read-only, credential-tight and ephemeral.

One command gets you to a shell with the agent pre-wired:

```sh
agentbox                          # shell in the sandbox, no agent
agentbox --agent opencode         # the opencode agent
agentbox --agent pi               # the pi coding agent
agentbox --agent claude           # the Claude Code agent
agentbox --agent antigravity      # Google Antigravity (binary: agy)
agentbox npm test                 # trailing arguments run inside
agentbox -- print-argv            # see the exact podman argv, no run
```

## What the sandbox is

| Property | How |
|---|---|
| Non-root | `--userns=keep-id`, no capabilities (`--cap-drop ALL`), `no-new-privileges`, `--read-only` rootfs |
| No ambient environment | `--unsetenv-all`, `--http-proxy=false` — podman's default proxy injection is credentialed and is explicitly disabled |
| Credential-tight env | only names the agent declares, and only when you ask with `--env` |
| Network | default `pasta` (outbound only); `none` for untrusted repositories; `host` warns loudly |
| Writable state | an ephemeral 0700 directory (on tmpfs when available) mounted at `/home/agent`, discarded on exit |
| Workspace | the launch directory, mounted rw at `/workspace` |
| Resource caps | memory `4g`, cpus `2`, pids `2048` by default, clamped |

Every flag fails safe: unknown modes, malformed mounts and credential-shaped
surprises are refused with a named reason, and every run can be recorded to an
audit log.

## How agent configuration gets in

How the agent's *host* configuration gets in is the crux. The agents need
different treatment because their on-disk layouts differ.

**opencode** keeps configuration and secrets in separate places:
`~/.config/opencode/` (mounted read-only) vs `~/.local/share/opencode/` — which
holds `auth.json` — *never read at all*. A directory-level rule (never mount the
state dir) is stronger than a file deny-list, so opencode mounts its config.

**pi**, **claude** and **antigravity** keep configuration and credentials in one
directory, so mounting any of those directories would hand the sandbox live
secrets. They are *seeded* instead from an **allow-list** — a file that is not on
the list is never read, copied or hashed. Where a seeded file may carry inline
credentials, it is rewritten first to strip credential-shaped keys:

```
pi           ~/.pi/agent/
  settings.json       seeded, apiKeys removed
  models.json         seeded, providers.*.apiKey removed
  models-store.json   seeded unchanged
  auth.json / oauth.json / oauth.json.migrated / trust.json   NEVER

claude       ~/.claude/
  settings.json       seeded, credential-shaped keys removed
  keybindings.json    seeded unchanged
  .credentials.json / .claude.json / history.jsonl / projects / plugins   NEVER

antigravity  ~/.gemini/
  antigravity-cli/settings.json     seeded, credential-shaped keys removed
  antigravity-cli/keybindings.json  seeded unchanged
  antigravity-oauth-token / oauth_creds.json / google_accounts.json
  trustedFolders.json / installation_id / state.json / history      NEVER
```

The boundary that blocks the rest of each directory is the allow-list itself,
which is auditable: every seeded file's size and SHA-256 go to the audit log.

For claude, `CLAUDE_CONFIG_DIR` points at the ephemeral container copy, so even
`.claude.json` (account state and per-project trust) is never read from the host.
antigravity has no documented relocation variable; the entrypoint is told the
seed destination explicitly.

## Security notes you should read

1. **The workspace is writable.** The blast radius for a hostile agent is the
   project tree it is asked to work on — that is the feature. An agent that is
   *remote* (reads/writes code and coins, not just a token conversation) has
   no other writable host surface: rootfs is ro, HOME evaporates, nothing on
   disk survives. `trust.json` (pi) is never seeded precisely because it is the
   facility by which a repository gains high trust state. When even that tree
   must not be touched, `--read-only-workspace` mounts it `:ro` and
   `--workspace DIR` narrows the run to a subdirectory; both are validated by
   the same deny-list as a launch directory.
2. **"Trusted vs untrusted agent" is not decided for you.** By default, host
   configuration that carries credential-shaped keys (`cli.json`,
   `service.json`) is mounted read-only with an audit warning
   (`warning [mount] … credential-shaped keys`). If your adversary is the agent
   itself, run with `--strict-config` to upgrade those warnings into refusals.
   `doctor` prints the mode explicitly.
3. **Loopback-based local providers do not work under pasta.** pasta shares no
   host loopback, so a pi/ollama setup at `127.0.0.1:11434` on the host is
   unreachable from the sandbox. That is isolation doing its job; the provider
   must be reachable by name/IP or the sandbox must run it.
4. **`--no-user-config` is the strongest mode.** No host path is read, mounted
   or seeded, and the agent is expected to fail to authenticate (or to use `--env`).
5. **The launch directory is validated like any mount:** `/`, `$HOME`, and any
   ancestor or descendant of a protected path (`~/.ssh`, `~/.aws`, `~/.pi`,
   `~/.claude`, `~/.gemini`, `~/.local`, `/run/user`, …) are refused. A symlinked
   project dir resolves first, so `cd ~` cannot be smuggled.
6. **Flags before command; `--` to escape.** Reserved words (`exec`, `images`,
   `doctor`, `version`) are recognized only in first position, so
   `agentbox exec foo` runs the `exec` subcommand and
   `agentbox -- exec foo` runs the program `exec` inside the sandbox.
7. **Config symlinks are followed, and refused, in the open.** A link such as
   `~/.config/opencode/skills -> …/agent-skills/skills` is followed even when it
   lands on another volume, and is mounted read-only at its own path. A link
   resolving outside your home — or into a deny-listed path such as `~/.ssh` —
   is *skipped*, never mounted: it is printed to stderr, listed by `doctor`, and
   recorded in the audit log, so a missing skills directory is explained rather
   than discovered.

## Commands

```
agentbox [flags] [--] [command...]   run (the default)
agentbox exec <name> -- <command>    execute into a live sandbox
agentbox images build [base opencode pi claude antigravity]
agentbox doctor                      report what a run would use
agentbox version
```

Flags: `--agent`, `--workdir`, `--image`, `--hostname` (default
`agentbox-<agent>`), `--no-user-config`, `--env NAME`
(repeatable, allow-listed), `--mount SRC:DST[:ro|rw]` (deny-listed, ro default),
`--workspace DIR` (mount a subdirectory instead of the launch dir),
`--read-only-workspace` (mount the workspace `:ro`),
`--network`, `--memory`, `--cpus`, `--pids-limit`, `--config FILE`,
`--strict-config`, `--print-argv`, `--audit-log FILE`, `--shell`.

### `--config FILE`

An explicit project configuration file. **It is never auto-discovered**: a
config file picked up from the working directory would be remote policy — a
clone could choose the agent, network, mounts and credentials for a run you
believe you control. The file may *request* things; policy still decides.

## Building

```sh
make install            # build and install to /usr/local/bin
make install PREFIX=~/.local
agentbox images build   # base, opencode, pi, claude, antigravity
```

`make install` places one file on disk: the binary carries the Containerfiles,
`entrypoint.sh` and the seccomp profile inside it. `PREFIX` (default
`/usr/local`, so use `sudo make install` there) selects the prefix and `DESTDIR`
is honoured for packaging; `make uninstall` removes just the binary.

The Containerfiles and `entrypoint.sh` are compiled into the binary, so a
downloaded `agentbox` builds its own images with no checkout and no `image/`
directory beside it. The same files live in `image/` because they are the
reviewable artifact: `image/containerfile_test.go` audits the digests and
versions they pin. `AGENTBOX_IMAGE_DIR` points a build at a directory instead,
for iterating on a Containerfile; like `--config`, it is never discovered
automatically, because whatever happened to sit next to the executable would
otherwise decide what gets built.

The base image is deliberately slim: it carries only what the entrypoint and the
agent installers need. Each agent image adds exactly one runtime — the agent's
pinned release artifact, checked against a digest recorded in the Containerfile.
That keeps a Node runtime out of the opencode, claude and antigravity images.

### Image references

Images are addressed by **fully-qualified name**. Podman does not default an
unqualified name to Docker Hub the way Docker does: it resolves the name against
the host's `unqualified-search-registries` list, which is not configured here, so
a short name selects a different image on a different machine.

```
opencode     localhost/agentbox/opencode:latest
pi           localhost/agentbox/pi:latest
claude       localhost/agentbox/claude:latest
antigravity  localhost/agentbox/antigravity:latest
base/shell   localhost/agentbox/base:latest
```

`localhost/` is the registry podman gives to locally built images. `--image` and
the config `image:` key accept only fully-qualified names; an unqualified
override is refused with the reason. The opencode image may be replaced with the
upstream build at `docker.io/openeuler/opencode:<tag>` (pinned by digest).

## Layout

```
cmd/            CLI: argv split, root, doctor, images, exec, version
internal/agent  agent registry — DATA only, no decisions (allow-lists, mounts policy)
internal/policy the single decision point: Request → ResolvedSpec | Refusal
internal/podman argv renderer + invariant assertions + run
internal/session staging (seeds, ephemeral HOME), audit, execution
internal/audit  redacting JSON decision records
internal/fsx    filesystem seam for policy tests
internal/config explicit YAML loading (strict, unknown keys rejected)
image/          Containerfiles + entrypoint (embedded in the binary)
```

## License

MIT. See [LICENSE](LICENSE).