#!/bin/sh
# container-agent entrypoint.
#
# Runs inside the sandbox as the keep-id (non-root) user and does two things
# before handing off to the command:
#
#   1. Creates the writable state directories with mode 0700.
#
#      A bare --tmpfs is 1777 (world-writable), and podman rejects uid=/gid= on
#      --tmpfs, so there is no way to set ownership or mode at mount time. Doing
#      it here is what keeps the tempting "fix" — mounting the tmpfs world- or
#      group-writable so the agent can write — from ever being necessary. The
#      argv invariants reject loosened tmpfs modes for the same reason.
#
#   2. Copies allow-listed seed files from the read-only staging mount into the
#      agent's configuration directory.
#
#      Agents that keep configuration and credentials in one directory cannot be
#      mounted read-only (secrets would cross) and cannot be mounted read-write
#      (host state would be written). Staging read-only and copying into an
#      ephemeral directory resolves that: the container can rewrite its settings,
#      and nothing it writes survives the exit.
#
# Permission failures are tolerated: the opencode configuration directory is a
# read-only bind mount, and chmod on it is expected to fail.

set -eu

umask 077

ensure_dir() {
	d="$1"
	[ -n "$d" ] || return 0
	mkdir -p "$d" 2>/dev/null || true
	chmod 700 "$d" 2>/dev/null || true
}

: "${HOME:=/home/agent}"
ensure_dir "$HOME"

for d in \
	"${XDG_CONFIG_HOME:-$HOME/.config}" \
	"${XDG_DATA_HOME:-$HOME/.local/share}" \
	"${XDG_STATE_HOME:-$HOME/.local/state}" \
	"${XDG_CACHE_HOME:-$HOME/.cache}" \
	"${PI_CODING_AGENT_DIR:-}" \
	"${PI_CODING_AGENT_SESSION_DIR:-}"
do
	ensure_dir "$d"
done

SEEDS=/run/container-agent/seeds
if [ -d "$SEEDS" ] && [ -n "${PI_CODING_AGENT_DIR:-}" ]; then
	ensure_dir "$PI_CODING_AGENT_DIR"
	cp -a "$SEEDS"/. "$PI_CODING_AGENT_DIR"/ 2>/dev/null || true
fi

exec "$@"
