#!/usr/bin/env bash
#
# Enforce coverage floors for the security-critical packages and an overall
# floor. Reads `go test ./... -cover` output for the per-package numbers and the
# generated profile for the cross-package total.
#
# Floors are deliberately set on the packages whose correctness is the security
# claim (policy, podman, audit, session), not on glue packages.
set -euo pipefail

cd "$(dirname "$0")/.."

COVER_PROFILE="${COVER_PROFILE:-coverall.out}"
TOTAL_MIN="${TOTAL_MIN:-75}"

# package suffix -> minimum percent
FLOORS=(
  "internal/policy:90"
  "internal/podman:90"
  "internal/audit:90"
  "internal/session:85"
)

out="$(go test ./... -cover -count=1 2>&1)" || { echo "$out"; exit 1; }
echo "$out"

fail=0

pkg_pct() {
  # $1 = package suffix; prints percent or empty
  printf '%s\n' "$out" | while IFS= read -r line; do
    case "$line" in
      *coverage:*) ;;
      *) continue ;;
    esac
    local pkg pct
    pkg="$(printf '%s' "$line" | grep -oE 'agentbox[^[:space:]]*' || true)"
    pct="$(printf '%s' "$line" | grep -oE 'coverage: [0-9.]+' | grep -oE '[0-9.]+' || true)"
    case "$pkg" in
      */"$1") printf '%s' "$pct" ;;
    esac
  done
}

for entry in "${FLOORS[@]}"; do
  pkg="${entry%%:*}"
  min="${entry##*:}"
  got="$(pkg_pct "$pkg")"
  if [ -z "$got" ]; then
    echo "FAIL: $pkg reported no coverage line" >&2
    fail=1
    continue
  fi
  if ! awk -v g="$got" -v m="$min" 'BEGIN { exit !(g+0 >= m+0) }'; then
    echo "FAIL: $pkg coverage $got% < floor $min%" >&2
    fail=1
  else
    echo "ok:   $pkg coverage $got% >= $min%"
  fi
done

if [ -f "$COVER_PROFILE" ]; then
  total="$(go tool cover -func="$COVER_PROFILE" | tail -1 | grep -oE '[0-9.]+' | tail -1)"
  if ! awk -v g="$total" -v m="$TOTAL_MIN" 'BEGIN { exit !(g+0 >= m+0) }'; then
    echo "FAIL: total coverage $total% < floor $TOTAL_MIN%" >&2
    fail=1
  else
    echo "ok:   total coverage $total% >= $TOTAL_MIN%"
  fi
fi

exit "$fail"
