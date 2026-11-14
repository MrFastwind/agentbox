# AGENTS.md

Guidance for agents working in this repository. Read this before changing code.

## What this project is

`agentbox` runs a coding agent (`opencode`, `pi`, `claude`, `antigravity`)
inside a deliberately small, read-only, rootless-podman sandbox. The security
properties are the product: non-root, all capabilities dropped, no ambient
environment, credential-tight config handling, ephemeral writable state, and a
workspace that is the only durable writable surface.

Module: `agentbox` (Go 1.27). Binary: `agentbox`. The only runtime dependency is
`gopkg.in/yaml.v3`; prefer the standard library.

## Commands

```sh
make build        # go build ./...
make vet          # go vet ./...
make test         # go test ./...
make test-race    # go test -race ./...
make cover        # cross-package coverage profile + total
make cover-check  # enforce per-package coverage floors
make fmt          # gofmt -w .
make lint         # vet + gofmt check
```

Run `make lint` and `make test-race` before claiming a change is done.
`make cover-check` is the CI gate. Integration tests need a built image and are
skipped unless `AGENTBOX_INTEGRATION=1` (see `internal/session/integration_test.go`).

## Architecture: one decision point

```
cmd/                 CLI dispatch, flag precedence, doctor, images, exec, version
internal/agent       DATA ONLY: per-agent registry (paths, seed allow-lists, env names)
internal/policy      THE decision point: Request -> ResolvedSpec | Refusal
internal/session     boot: resolve -> revalidate -> stage -> argv -> assert -> audit -> run
internal/podman      argv renderer, invariant assertions, podman invocation
internal/audit       redacting newline-delimited JSON decision records
internal/config      explicit YAML loading; unknown keys rejected
internal/fsx         filesystem seam (real + fake) so policy is testable without a host
image/               Containerfiles, entrypoint, supply-chain pin tests
```

The flow is:

`cmd` parses input → `policy.Resolver.Resolve` decides everything → `session.Boot`
revalidates (TOCTOU), stages seeds/ephemeral HOME, renders argv, calls
`podman.Assert`, writes the audit record → `podman.Run`.

**`internal/policy` is the only place allowed to make a security decision.**
`internal/agent` may declare facts; it must not decide. Do not put a
per-agent toggle in the registry that can weaken a universal invariant (for
example, there is deliberately no "follow symlinks" flag).

Every consumer — argv renderer, `doctor`, `--print-argv`, audit log — reads the
same `policy.ResolvedSpec` so they cannot disagree about what was decided.

## Invariants that must not be weakened

- Rootfs is read-only; `--cap-drop ALL`, `no-new-privileges`, `--unsetenv-all`,
  `--http-proxy=false`, `--ulimit core=0` and a seccomp profile are always-on.
- Rootless only (`--userns=keep-id`). Never add `--privileged`, `--cap-add`,
  `--device`, `--secret`, `--env-file`, `seccomp=unconfined`, `label=disable`,
  or any other escape in `internal/podman/invariants.go`.
- At most **one** user-influenced writable mount (the workspace, or one explicit
  `--mount`). The ephemeral HOME is the only other writable mount and must be
  `origin: "state"` at `/home/agent`.
- Seed files are an **allow-list**: a file not named in `SeedSpec` is never read,
  copied or hashed. Keep it that way; do not switch to scanning a directory.
- Images must be fully qualified (`localhost/agentbox/...`, `docker.io/...`).
  Never accept or emit a short image name.
- The launch directory, mounts and symlink targets are checked against the
  deny-list. `--config` is never auto-discovered.
- Fail closed. Unknown modes, malformed input and credential-shaped surprises
  become a named `policy.Refusal`; do not silently fall back to a weaker mode.
- Never log or print secret values. The audit log records names, sizes, hashes
  and removed keys — never bytes or `EnvPair.Value`.

If a test would have to be relaxed to make a change pass, the change is probably
wrong. `podman.Assert` and the Containerfile pin tests exist specifically to fail
the build when a sandbox guarantee is edited away.

## Making common changes

**New flag / option**
1. Add it in `cmd/root.go` (and the subcommand if relevant).
2. Add it to `internal/config.File` + `agentbox.yaml.example` only if it belongs
   in project config; note the flag > config > default precedence.
3. Add it to `policy.Request` / `ResolvedSpec`, and decide/validate it in
   `internal/policy`.
4. Render it in `internal/podman/argv.go`; extend `Assert` if it affects a
   guarantee.
5. Surface it in `doctor`/`--print-argv` and the audit record when it is
   security-relevant.
6. Add tests at the policy level (with `fsx.Fake`) and the cmd level.

**New agent**
1. Add a data-only `Definition` under `internal/agent/` (config strategy, seed
   allow-list, declared env names, fully-qualified image) and register it.
2. Add `image/Containerfile.<agent>` and wire it into `agentbox images build`.
   Pin the agent version and verify a release artifact against a digest recorded
   in the Containerfile; the installer's "latest" is not a pin. Keep the base
   image slim and add only the runtime that agent needs.
3. Add image tests for any pin or supply-chain guarantee.
4. Update `README.md` (behaviour and the security notes) and this file if the
   architecture changes.

**New refusal**
Use `policy.Refusal` with a `RefusalKind`, subject and reason; fatal refusals
abort, non-fatal ones are warnings visible in `doctor`, `--print-argv` and audit.
Error text is lowercase, specific, and wrapped with `%w` where it comes from a
lower layer.

## Testing conventions

- Table-driven tests with `t.Run`, named after the behaviour being protected.
- Test security paths on both sides: the happy refusal **and** malformed/missing
  input, wrong origin, and unexpected filesystem state.
- Use `internal/fsx.Fake` for policy tests; never read the real home directory.
- Use the seams in `cmd/seams.go` (`execCommand`, `runSession`) so CLI tests do
  not need podman.
- Coverage floors (CI-enforced): `internal/policy`, `internal/podman`,
  `internal/audit`, `internal/session` ≥ 90%; total ≥ 75%.
- Add a regression test with every behaviour change. For a security fix, the
  test should fail if the fix is reverted.

## Style

- `gofmt` is the formatter; `make lint` must pass.
- Comments explain **why** a decision exists, especially for security choices.
  Do not restate the code.
- Keep the layering: `cmd` does I/O and precedence, `policy` decides, `podman`
  renders, `session` stages. No package reaches around the layer beside it.
- Prefer small, explicit functions and named constants over magic strings.
- Keep `README.md` and `PLAN.md` honest. `PLAN.md` §0 records drift from the
  original plan; if implementation and docs disagree, fix the docs (or record
  the drift), but keep the code normative.

## Do not commit or edit

- The built binary `agentbox`, `coverall.out`, `coverage.out` (gitignored).
- `.opencode/` working notes and node_modules (gitignored).
- Containerfile digests, pinned versions, or Dockerfile lint-test expectations
  without a documented reason and a passing build.

## Definition of done

- `make lint` passes.
- `make test-race` passes.
- `make cover-check` passes.
- New decisions are visible in `doctor`/`--print-argv` and the audit log.
- README/PLAN reflect the behaviour if it changed.
