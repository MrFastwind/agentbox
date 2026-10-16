# agentbox — Implementation Plan

**Status:** Implemented (v0.1.0). This document is the working design before
build; drift discovered during implementation is recorded in [§0 — Implemented drift](#0-implemented-drift)
so the plan does not silently describe something the code no longer does.
**Source:** the original project README (was committed under the misspelled
name `READAME.md`; renamed to `README.md`).

---

## 0. Implemented drift

Changes the build forced onto the plan, with the reason each one was necessary.
The code is normative; this section keeps the plan from lying.

1. **Network default is `pasta`, not `slirp4netns` or `host`.** Podman 6 removed
   `slirp4netns` entirely (`Error: slirp4netns support has been removed, use
   --network=pasta`). `pasta` is podman's rootless default, gives the same
   isolation shape (outbound only, no LAN/tailnet/host-loopback), and actually
   runs. `slirp4netns` is kept as a selectable mode with a warning for older
   podman. `host` stays selectable-with-warning.
2. **Writable state is NOT a `--tmpfs`.** Podman 6.1.2 creates a `--tmpfs`
   owned by container `0:0` mode `0700` and rejects `uid=`/`gid=` on the mount,
   so under `--userns=keep-id` the agent cannot write its own HOME — verified
   empirically. State is instead an ephemeral directory created by
   `internal/session` (0700, owned by the invoking user, on a host tmpfs such
   as `/dev/shm` when available), bind-mounted at `/home/agent`, removed on
   exit. The directory's subpaths are pre-created 0700 so that `XDG_*` parents
   are writable and the ro config mounts land on user-owned mountpoints.
   Security outcome is the same: writable state is ephemeral and discarded.
3. **A config-directory symlink whose target escapes the allowed prefixes is
   skipped with a warning, not fatal.** Real host: `~/.config/opencode/skills`
   points onto a different mount. Refusing the whole run made a legitimate
   layout unusable; not mounting the link is safe and auditable.
4. **`--strict-config` turns the S-30 credential-assertion from a warning into
   a refusal.** The plan's status for configuration that carries
   credential-shaped keys (claude.json, service.json) was an open question —
   the "is the sandboxed agent trusted?" fork. The flag makes the answer
   explicit rather than guessed.
5. **`/run` and `/var/run` are not blanket deny prefixes.** `/run/media` is a
   legitimate project location; only `/run/user`, `/run/podman`,
   `/run/containers`, `/run/secrets` and the podman socket paths are denied.

---

## 1. Problem

A terminal application that deploys a small container with volumes already defined, so an
agent can be worked on directly inside a sandboxed shell.

Target features from the README:

1. Single command to execution
2. Command the application directly to the shell
3. Best security to contain agent operations

The repository currently contains **only** `READAME.md`. This is a greenfield build.

---

## 2. Verified environment findings

Measured on the target host, not assumed. These constrain the design.

### Backend

| Finding | Consequence |
|---|---|
| `podman` 6.1.2, rootless works (`Rootless=true`, runc, overlay) | Use podman as the backend |
| `/usr/bin/docker` is a 228-byte shim that `exec`s podman | Do **not** target the Docker socket/API; target the podman CLI |
| `unqualified-search-registries` is **unset** in `registries.conf`; locally built images are stored as `localhost/...` | References must be fully-qualified image names (FQIN: registry + namespace + name + tag/digest). Short names are not reliably resolvable and Docker's Docker-Hub-default semantics do not apply. See §6a.1 |
| Rootless podman `--network=host` exposes `enp42s0` **and `tailscale0`** | Host networking grants LAN + tailnet reach. See §10 R1 |
| Go 1.27.1 present | Static single binary, no cgo |
| `fastwind:100000:65536` in `/etc/subuid`, userns enabled | Rootless subuid mapping is available |

### Agent: opencode

| Finding | Consequence |
|---|---|
| `/usr/bin/opencode` is a **glibc-dynamically-linked** ELF | Base image **must** be Debian/Ubuntu. Alpine/musl will not run it |
| `~/.config/opencode/` holds static config only (`opencode.json`, `agents/`, `command/`, `docs/`) | Safe to auto-mount `:ro` |
| `~/.local/share/opencode/` holds **mutable state and secrets** (`opencode.db`, `snapshot/`, `storage/`, `auth.json`, `account.json` at `0600`) | Must **never** be mounted. Redirect the path instead |
| Honors `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME`, `OPENCODE_CONFIG_DIR` | Writable state redirects cleanly to container-local storage |
| `~/.config/opencode/skills` is a **symlink out of the config dir** to `~/media/.../agent-skills/skills` | A naive bind-mount leaves a **dangling symlink** in the container. Must be resolved explicitly |
| Honors `OPENCODE_API_KEY` | Credentials can cross as env instead of a file |

### Agent: pi

| Finding | Consequence |
|---|---|
| `@earendil-works/pi-coding-agent` v0.87.1, an **npm package**; `~/.local/bin/pi` is a symlink to `dist/bundle/cli.js` | Cannot be copied in as a single binary. The image needs **Node.js** plus the package |
| `engines.node >= 22.19.0`; host runs Node v26.10.0 | Image must ship Node ≥ 22.19.0 |
| **One directory holds everything**: `~/.pi/agent/` contains `auth.json` (`0600`), `settings.json`, `models-store.json`, and `sessions/` **together** | The opencode-style config/state split **does not exist**. See below |
| `PI_CODING_AGENT_DIR` redirects the **entire** agent dir (`dist/config.js:getAgentDir()`); there is no per-file override | Cannot mount the dir `:ro` (breaks sessions) and cannot redirect state away from config (secrets travel with it) |
| `PI_CODING_AGENT_SESSION_DIR` exists as a separate session override | Partial escape hatch for the one dir that matters most |
| `PI_BUNDLED_NODE` is a compile-time flag, not a runtime switch | A self-contained node build is not something we can simply toggle |
| Honors standard provider env vars: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENCODE_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `GROQ_API_KEY`, `MISTRAL_API_KEY`, `XAI_API_KEY` | Credentials can cross as env; no file mount needed |

### The config/state split, and where it breaks

For opencode the host layout cleanly separates two kinds of state, and they must be treated
oppositely:

- **Config** (`~/.config/opencode/`) — read, never written. Mountable `:ro`.
- **State + secrets** (`~/.local/share/opencode/`) — written constantly; holds session
  databases and `0600` credential files. Never mounted; the path is redirected to
  container-local storage so writes land on tmpfs and vanish on exit.

**pi has no such split.** `auth.json`, `settings.json`, and `sessions/` all sit in
`~/.pi/agent/`, and `PI_CODING_AGENT_DIR` moves the whole directory as a unit. So the
mechanism that protects opencode cannot protect pi:

- Mount `~/.pi/agent/` `:ro` → **`auth.json` is now inside the container**, and sessions
  break.
- Redirect `PI_CODING_AGENT_DIR` to a tmpfs → **config is lost**, so the agent comes up
  with no settings, no themes, no tools.

The registry must therefore model three categories per agent, not two:

| Category | opencode | pi |
|---|---|---|
| Config to mount `:ro` | `~/.config/opencode/` | **None mountable as a dir** |
| Secrets | env / never mount | env only |
| Mutable state | redirect `XDG_DATA_HOME` | `PI_CODING_AGENT_SESSION_DIR` to tmpfs |

For pi, the working v1 answer is: **seed config by file, not by directory.** Rather than
mounting `~/.pi/agent/`, copy the individual non-secret config files into the container's
`PI_CODING_AGENT_DIR` at start-up, explicitly excluding `auth.json`, and point
`PI_CODING_AGENT_SESSION_DIR` at a tmpfs. A deny-listed filename list is the security
boundary here, which is weaker than a directory-level rule and must be treated as such.

This is a real asymmetry between the two agents, and the registry exists to make it
explicit per agent rather than to pretend it is uniform.

---

## 3. Goals / Non-goals

**Goals**

- One command from a project directory to a working agent shell.
- Automatic, correct-by-default wiring of agent config, with no manual mount flags.
- Deny-by-default for everything *not* explicitly wired.
- Zero ambient host state: nothing persisted, nothing silently mounted.

**Non-goals (v1)**

- Multi-tenant orchestration, scheduling, or a daemon/server API.
- Windows/macOS support (the rootless podman path is Linux-specific).
- Reimplementing podman's security model; we harden and wrap, we do not fork.

---

## 4. Invocation model (the default)

The program's default invocation **is** the command. There is no required subcommand.

```bash
agentbox                      # → container, interactive shell
agentbox --agent opencode     # → container, opencode
agentbox --agent pi           # → container, pi
agentbox ls -la               # → container, runs `ls -la` and exits
agentbox npm test             # → container, runs `npm test` and exits
agentbox --no-user-config --agent opencode   # no host agent config at all
```

Trailing arguments are passed **through to the agent/shell inside the container**, not
interpreted by agentbox. With no trailing arguments, an interactive shell starts.

### Per-agent behaviour (user config wired in — the default)

```bash
agentbox --agent opencode
#   mounts ~/.config/opencode/            → $XDG_CONFIG_HOME/opencode   :ro
#   tmpfs at $XDG_DATA_HOME               → sessions/db land here, discarded
#   config symlinks (skills/) resolved and mounted :ro

agentbox --agent pi
#   copies ~/.pi/agent/{settings,models-store,models}.json + themes/ tools/ prompts/
#         → $PI_CODING_AGENT_DIR           (auth.json explicitly EXCLUDED)
#   tmpfs at $PI_CODING_AGENT_SESSION_DIR → sessions discarded
#   requires node >= 22.19.0 in the image
```

### Auto-mounts applied on every run

| Host path | Container path | Mode | Rationale |
|---|---|---|---|
| **Launch directory** (cwd) | `/workspace` | `:rw` | This is the project being worked on |
| Agent config, per registry (§6) | agent-specific | `:ro` or seeded | opencode: dir mount. pi: per-file copy (§2) |
| Resolved symlink targets inside that config | same relative location | `:ro` | Prevents dangling symlinks (§2) |

**Nothing else from the host is visible.** Writable agent state goes to a container-local
tmpfs; no host path is mounted to receive it. `--no-user-config` removes the two config rows
entirely (see below).

### `--no-user-config` — run without any host agent config

The default wires in the user's own agent configuration, because an agent with no settings,
no agents/skills, and no provider defaults is rarely the agent you wanted. But that wiring
is a convenience built on a file-level trust decision, and for pi in particular it is the
weaker of the two boundaries (§7). So it must be possible to turn it off completely.

```bash
agentbox --no-user-config --agent opencode
agentbox --no-user-config --agent pi
agentbox --no-user-config             # bare sandbox, nothing agent-specific
```

With the flag set:

- **No host config path is read, mounted, or seeded.** For opencode, `~/.config/opencode/`
  is not mounted. For pi, no file from `~/.pi/agent/` is copied — the `auth.json` deny-list
  question becomes moot, and so does the whole file-level weakness.
- The agent starts from a **clean, empty config dir** inside the container, on a tmpfs.
- No API-key env var crosses unless explicitly requested via `--env`. The default remains
  "no credentials".
- `XDG_CONFIG_HOME` / `PI_CODING_AGENT_DIR` point at container-local empty directories, so
  anything the agent writes stays in the container and disappears on exit.

What this costs, stated plainly: the agent comes up with **no** custom agents, skills,
prompts, themes, tools, MCP servers, or provider/model defaults. For opencode that means no
`opencode.json`; for pi, no `settings.json` or `models-store.json`, so pi will need a model
selected by flag or env. This is a strictly more isolated mode and a genuinely different
experience, not a degraded default.

`doctor` should report which mode a given invocation will use, and `--print-argv` must show
it plainly, so it is never ambiguous whether host config was wired in. A generated minimal
config (§10.8) would make this mode useful rather than merely bare.

### Exit semantics

Exit code of the inner command is propagated. `SIGINT`/`SIGTERM` tear the container down
regardless of the agent's exit state, so an interrupted run never leaves a container behind.

---

## 5. CLI surface

```
agentbox [flags] [--] [command...]   # the default: boot and run
agentbox exec <name> -- <cmd>        # run in an already-live sandbox
agentbox images build                # build/refresh the sandbox image
agentbox doctor                      # verify podman, userns, image, agent paths
```

Supporting flags (all optional; the defaults in §4 need none of them):

```
--agent NAME            agent to launch instead of a shell
--workdir DIR           override the auto-detected launch directory
--image REF             override the sandbox image (FQIN only, §6a.1; validated)
--no-user-config        read/mount/seed NO host agent config; empty config in container
--env NAME              pass one host env var into the container (repeatable, explicit)
--mount SRC:DST[:ro|rw] extra mount, deny-list validated, defaults to :ro
--network MODE          host (default) | none | slirp4netns   [see §10]
--memory --cpus --pids-limit
--config FILE           agentbox.yaml
--print-argv            print the exact podman argv and exit (debugging/audit)
```

---

## 6. Architecture

```
agentbox/
├── go.mod
├── main.go
├── cmd/                    # cobra: root (default), exec, images, doctor
├── internal/
│   ├── podman/             # argv builder + exec wrapper; never shell-interpolated
│   ├── policy/             # mount validator + deny-list        [unit-tested]
│   ├── agent/
│   │   ├── registry.go     # per-agent definition table (the extension point)
│   │   ├── config.go       # config-dir resolution, symlink following
│   │   ├── seed.go         # per-file config seeding (pi path)
│   │   └── env.go          # XDG/PI_* redirection, env allowlist
│   ├── session/            # ephemeral container lifecycle
│   └── config/             # agentbox.yaml loading
├── image/
│   ├── Containerfile.base     # debian-slim + git, rg, fd, build tools
│   ├── Containerfile.opencode # base + opencode binary
│   └── Containerfile.pi       # base + node>=22.19.0 + pi-coding-agent
├── agentbox.yaml    # example project config
└── PLAN.md
```

### 6a. Agent registry

The registry is a table, not a switch statement. Each entry declares its own strategy.

#### 6a.1 Program ↔ container mapping

Each program maps to exactly one container image, stored as a **fully-qualified image name**
(FQIN: registry host + namespace + name + tag/digest). Short names are forbidden in the
registry and in config, because the same short string resolves differently per host: under
Docker `openeuler/opencode` means `docker.io/openeuler/opencode`, but under podman it depends
on the host's `registries.conf` search list (unset on the target host, §2). An
environment-dependent reference is a supply-chain ambiguity, not a convenience.

| Program | Default container image (FQIN) | Built from | Upstream equivalent (FQIN) |
|---|---|---|---|
| `opencode` | `localhost/agentbox/opencode:latest` | `image/Containerfile.opencode` (glibc base) | `docker.io/openeuler/opencode:<pinned-tag>` |
| `pi` | `localhost/agentbox/pi:latest` | `image/Containerfile.pi` (`FROM docker.io/library/node:22-slim`) | none |

Rules:

- Locally built images are addressed as `localhost/...` (podman's build default) and run with
  `--pull=never`, so a same-named Hub image can never be silently substituted.
- Upstream references (`docker.io/openeuler/opencode`) are pinned by **digest**, not `latest`.
- `FROM` lines in the Containerfiles are FQINs too (`docker.io/library/node:22-slim`,
  `docker.io/library/debian:stable-slim`).
- `doctor` prints the resolved FQIN per program and **warns** when
  `unqualified-search-registries` is unset or any reference is a short name.
- The built-in table is the authority. A **user-global** config may reference one of these
  FQINs; a project-local config may only select a program, never name an image (S-21). A
  config-supplied image must pass the same FQIN + registry-host allowlist check as the table.

The registry entry that implements this mapping:

```go
type Agent struct {
    Name          string
    Image         string          // FQIN for this program, §6a.1 (localhost/agentbox/<name>)
    UpstreamImage string          // documented upstream equivalent, "" if none (opencode: docker.io/openeuler/opencode)
    ConfigMount   ConfigStrategy  // DirMount | FileSeed | None
    ConfigDir     string          // host dir to read config from
    ConfigEnv     string          // container-side config dir env var
    DenyFiles     []string        // never seed (pi: "auth.json")
    StateEnv      map[string]string  // PI_CODING_AGENT_SESSION_DIR → tmpfs, etc.
    EnvAllowlist  []string        // API keys permitted to cross
    FollowSymlinks bool           // opencode: true
}
```

Adding an agent is a table entry. It is not a branch in the mount logic. Three things this
structure absorbs without special-casing the call sites:

- Two config strategies (`DirMount` vs `FileSeed`) — pi forces the second to exist.
- `None` as a first-class strategy — this is what `--no-user-config` selects, so the
  isolated path is the *same* code path with different registry data, not a parallel
  implementation that can drift.
- Per-agent state env and key allowlists, which differ between the two agents.

### 6b. Two images, not one

opencode is a self-contained native binary; pi is an npm package needing Node. Bundling
both means every user carries Node even when running opencode. Separate images keep each
minimal; a shared `Containerfile.base` avoids duplicating the toolchain layer.

Both are our own images, mapped in §6a.1. The mapping also records upstream equivalents so the
pair is discoverable and swappable: `docker.io/openeuler/opencode` is the openEuler-built
official image for the opencode program and may be referenced by a **user-global** config in
place of `localhost/agentbox/opencode`; pi has no upstream image, so
`localhost/agentbox/pi` is its only mapping. The defaults are the locally built FQINs,
so an unqualified name never reaches podman's runtime argv.

**Design notes**

- `internal/podman` builds an `[]string` argv and `exec`s directly. No `sh -c`, no string
  concatenation of user paths. This removes a whole class of injection bugs.
- `internal/agent/registry.go` is the extension point. Each agent declares its config dir,
  its state dir, and its required env. Adding an agent means adding a table entry, not
  branching the mount logic.
- `internal/policy` is pure and side-effect-free, so it is exhaustively unit-testable
  without a container runtime.
- TTY passthrough uses inherited stdin/stdout/stderr; no pty proxy needed for v1.

---

## 7. Security model

### Container hardening baseline (always applied)

```
--userns=keep-id                 non-root; host uid preserved for correct file ownership
--cap-drop=ALL                   no capabilities
--security-opt=no-new-privileges  no setuid escalation
--read-only                      immutable root filesystem
--tmpfs /tmp --tmpfs /run        writable scratch, never on disk
--tmpfs $XDG_DATA_HOME           agent writable state, discarded on exit
--pids-limit                     process-count cap
--memory --cpus                  resource caps
--rm                             container removed on exit
```

State tmpfs is per-agent: `$XDG_DATA_HOME` for opencode, `$PI_CODING_AGENT_SESSION_DIR`
for pi. The registry decides which apply.

### Deny-list (rejected even when explicitly requested)

`/` · `$HOME` · `~/.ssh` · `~/.aws` · `~/.gnupg` · `~/.local/share` · `~/.pi` ·
`~/.config/**/auth.json` · `~/.config/**/credentials*` · `/etc` · `/proc` · `/sys` ·
`/dev` · `/var/run/docker.sock` · `/run/user/*/podman.sock`

`~/.local/share` and `~/.pi` are denied **wholesale** because that is where agent
credential files live. This is the rule that enforces the config/state split from §2, and
it is why pi's config must be *seeded* rather than mounted.

Validation resolves symlinks **before** matching (via `filepath.EvalSymlinks` on the
fully-resolved absolute path). Matching on the literal user-supplied string is trivially
bypassed with a symlink and is not acceptable.

### Weaker boundary for pi — stated explicitly

opencode's secrets are protected by a **directory-level** rule: the containing directory is
never mounted, so a new secret file appearing later is still safe by default.

pi cannot get that guarantee. `auth.json` sits beside `settings.json`, so protecting it
depends on a **file-level** deny list. Two consequences, both of which are accepted
deliberately and should be visible in `doctor` output rather than buried in code:

- A credential file with a name not on the list would be seeded into the container.
- `--print-argv` plus `doctor` must show exactly which pi files were seeded, so a user can
  audit it. Relying on the deny list being complete is not sufficient on its own.

Longer term this argues for a pi upstream fix (a real `PI_CONFIG_DIR` separate from the
state dir), or a local credential broker. Tracked in §10.

### `--no-user-config` as the strict mode

The pi weakness above exists **only** in the default path. `--no-user-config` removes the
host config entirely, so no file-level allowlist is consulted at all and pi's secret
boundary becomes as strong as opencode's — the containing directory is simply never read.

This makes it the right flag for untrusted or shared workspaces, for running against a
repository you did not write, and for anyone who wants the sandbox's guarantees to be
auditable in one line rather than per-file. The cost is a bare agent with no custom agents,
skills, prompts, themes, tools, MCP servers, or model defaults (§4).

### What the `:rw` workspace actually costs

The launch directory is writable by the agent **by default**. This is a deliberate
usability choice — an agent that cannot write cannot do its job — but it should be stated
plainly: **blast radius is the project tree.** An agent can modify, delete, or corrupt any
file under the launch directory, including tracked source. Two consequences follow:

- The image and toolchain do **not** protect project files; only VCS, backups, or the
  `--workdir` override do.
- Users who want a read-only guarantee should launch from a scratch directory or a clean
  worktree, and should be told this in the docs rather than discovering it.

### Secrets

- Never mounted. `auth.json` / `account.json` / `credentials*` are on the deny-list, and
  `~/.pi` is denied as a whole directory.
- Only allowlisted environment variables cross into the container:

  | Agent | Allowed |
  |---|---|
  | opencode | `OPENCODE_API_KEY` (+ `OPENCODE_CONFIG` if explicitly set in project config) |
  | pi | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENCODE_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `GROQ_API_KEY`, `MISTRAL_API_KEY`, `XAI_API_KEY` |

  The host environment is never inherited wholesale. Absent a flag, **no** key crosses and
  the agent is expected to fail to authenticate — which is the safe default, and better
  than silently handing an agent working credentials.
- Agent config is configuration, not a secret: opencode's is mounted `:ro`, pi's is seeded
  per file.

---

## 8. Milestones

1. **Scaffold** — `go.mod`, cobra root with pass-through args, `version`, `doctor`.
   *Exit criterion:* `agentbox doctor` reports podman version, rootless status,
   userns, image presence, and the resolved config/state paths for **both** agents,
   including which mode (`--no-user-config` or not) a given invocation would use.
2. **Policy engine** — mount validator, deny-list, symlink resolution, unit tests.
   *Security core — implemented first, before any container is ever launched.*
3. **Pass-through + auto-mounts (opencode)** — cwd → `/workspace:rw`,
   `~/.config/opencode/` → `:ro` with symlink targets resolved, `XDG_DATA_HOME` → tmpfs.
   *Exit criterion:* `agentbox ls -la` works, a denied mount is rejected, and
   `~/.local/share/opencode/auth.json` is provably absent inside the container.
4. **Images** — `Containerfile.base` (glibc, git/rg/fd/build tools) plus
   `Containerfile.opencode` and `Containerfile.pi` (node ≥ 22.19.0 + pi-coding-agent);
   `agentbox images build` with local caching. All `FROM` and runtime references are
   FQINs (§6a.1); built images are tagged `localhost/agentbox/{opencode,pi}`.
5. **Registry + agent runners** — the `Agent` table (§6a) with all three strategies; seed
   pi's config per file excluding `auth.json`, point `PI_CODING_AGENT_SESSION_DIR` at tmpfs.
   *Exit criterion:* both `--agent opencode` and `--agent pi` start with working config,
   and neither container can read a host credential file.
6. **`--no-user-config`** — the `None` strategy end to end. *Exit criterion:* with the flag,
   `doctor` and `--print-argv` show no host config path at all, and a container booted this
   way cannot read any host agent config or credential file — for pi included.
7. **Config** — `agentbox.yaml` for per-project mounts, caps, agent selection,
   default agent, and whether user config is wired in.
8. **Docs and tests** — README with the threat model, the `:rw` workspace caveat, the
   config/state split, the weaker pi boundary, and what `--no-user-config` costs;
   integration tests booting a real sandbox and asserting deny-list enforcement for both
   agents in both config modes.

Each milestone ends with something runnable.

---

## 9. Risks and open questions

**R1 — Host networking undercuts the security goal (highest priority).**
Measured: rootless podman `--network=host` exposes `enp42s0` and `tailscale0`. An agent in
the sandbox can reach the LAN and the tailnet, not just the loopback. This contradicts
README feature #3. Mitigation is tracked as a nice-to-have in §10.

**R2 — Symlinked config directories.** `~/.config/opencode/skills` points outside the
config dir. If the registry mounts a config dir without following such links, the agent
gets a dangling symlink and fails confusingly. Milestone 3 must cover this case, and
`doctor` should surface unresolved links.

**R3 — pi's weaker secret boundary (highest priority after R1).** `auth.json` is protected
by a *file* deny list rather than a *directory* rule, because pi keeps config and secrets
in the same directory and `PI_CODING_AGENT_DIR` moves the lot. A credential file with an
unexpected name would be seeded into the container. Mitigations: make `doctor` and
`--print-argv` enumerate exactly what was seeded, so the boundary is auditable rather than
merely asserted; and note that `--no-user-config` sidesteps it entirely by never reading
the host directory. See §7 and §10.3.

**R4 — pi needs a Node runtime in the image.** `pi` is an npm package (`engines.node >=
22.19.0`), not a static binary. The pi image carries Node plus the package tree; the
opencode image deliberately does not, to keep each minimal (§6b). Version drift between
host and image is a real failure mode — the image's Node must satisfy the *pinned* pi
version's `engines`, and the pin should be recorded in the Containerfile.

**R5 — Symlinked config directories.** `~/.config/opencode/skills` points outside the
config dir. If the registry mounts a config dir without following such links, the agent
gets a dangling symlink and fails confusingly. Milestone 3 must cover this, and `doctor`
should surface unresolved links.

**R6 — Writable state is ephemeral.** State is redirected to a tmpfs (`XDG_DATA_HOME` /
`PI_CODING_AGENT_SESSION_DIR`), so sessions, snapshots, and caches do not survive exit.
Intentional and consistent with `--rm`, but it changes the feel of long agent runs and
must be documented.

**R7 — opencode image size.** A baked-in agent plus toolchains can reach GBs. Mitigated by
the split in §6b; revisit if either image proves impractical.

**R8 — Open question: agent credential scope.** If several agents or projects share a
sandbox, per-agent env allowlisting may not be fine-grained enough, and a short-lived
credential broker may be needed. Deferred until the threat model is exercised.

---

## 10. Nice to have (post-v1)

1. **Isolated egress mode — `slirp4netns` with a host alias.** *(the §9 R1 mitigation)*
   Rootless slirp4netns provides outbound internet and maps `10.0.2.2` to the host, so
   `--add-host host.docker.internal:10.0.2.2` reaches host services **without** the
   container ever getting a tap interface onto `tailscale0` or the LAN. Strictly more
   contained, and it would replace `--network=host` as the default.
2. Named persistent sessions with TTL-based auto-reaping (`ps` / `stop` / `rm`).
3. Short-lived credential broker for per-agent secret scoping. *(the §9 R3 mitigation)*
4. Opt-in persistence of agent state across runs (`--persist-state`).
5. Resource-usage reporting after exit (`--report`).
6. Pluggable backend interface (podman first, bwrap/systemd-nspawn later).
7. A variant base image for projects that want to pin their own toolchain.
8. Per-agent config *generation* (write a minimal `opencode.json` / pi settings into the
   container) so `--no-user-config` is not merely empty but sensibly provisioned.
