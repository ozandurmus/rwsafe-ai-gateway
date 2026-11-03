#!/usr/bin/env bash
# PRODUCT OWNER (PILOT_RUNBOOK.md step 14.5): the directory's address ranges for the control plane's egress, typed on the
# HOST-A terminal only. The ranges come from the directory or network team; they are a real network identifier, so they
# are never committed, pasted into chat or passed as a command argument (AGENTS.md 4.2, 8).
#
# Reads each range with `read -rs` (nothing is echoed): an IPv4 CIDR (for example a /24) or a single address; an empty
# line ends the list, at most 8 (a trailing CR from a Windows terminal is dropped). Each range is checked as it is typed
# (tools/pilot/directory_range.py: IPv4 inside RFC 1918 private space only, no prefix shorter than /16, nothing touching loopback, link-local, multicast, reserved or the cluster's pod and Service ranges,
# no overlap with an earlier one); a refused range is named by its number and rule only, and may be typed again. Then
#   ~/.config/<product>/pilot/directory.env   (both directories 0700, the file 0600)
# is replaced as a whole with one `DIRECTORY_CIDR=` line per range, and only the count is printed. The values travel
# only through pipes to directory_range.py (shell builtins, never a process argument), and neither is the file's path;
# a symbolic link in ~/.config/<product>/pilot/ is refused. Run it as the host account that
# renders (the orchestrator's account): tools/pilot/render.py reads the file from that account's home. Running it again
# replaces the file; deleting the file and rendering again closes the egress.
#
# Usage: tools/pilot/directory_range.sh
# Environment: PRODUCT (one-command override of product.env); DIRECTORY_ENV (another file, for tests)
# Exit: 0 written, 1 nothing written (no accepted range) or failed, 2 usage
set -euo pipefail
umask 077

# shellcheck source=tools/pilot/common.sh
. "$(dirname "$0")/common.sh"

if [ "$#" -ne 0 ]; then
  echo "usage: $0 (no arguments; the ranges are typed, never given as arguments)" >&2
  exit 2
fi
if [ "$(id -u)" = 0 ]; then
  echo "run as the host user, never as root (AGENTS.md section 8)" >&2
  exit 2
fi

CHECKER="${PILOT_REPO}/tools/pilot/directory_range.py"
# The file's path never becomes a process argument (it carries the account name in $HOME): directory_range.py takes
# the product's default path itself; DIRECTORY_ENV (tests only) names another.
WRITE_ARGS=(--write --product "${PRODUCT}")
if [ -n "${DIRECTORY_ENV:-}" ]; then
  WRITE_ARGS=(--write "${DIRECTORY_ENV}")
  SHOWN="the file named by DIRECTORY_ENV"
else
  BASE="${HOME}/.config/${PRODUCT}"
  # PR 54 review D-04: never through a symbolic link
  for d in "${BASE}" "${BASE}/pilot" "${BASE}/pilot/directory.env"; do
    if [ -L "${d}" ]; then
      echo "refused: ~/.config/${PRODUCT}/... holds a symbolic link; nothing written" >&2
      exit 1
    fi
  done
  mkdir -p "${BASE}/pilot"
  chmod 0700 "${BASE}" "${BASE}/pilot"
  # shellcheck disable=SC2088  # printed literally: the path without the account name in $HOME
  SHOWN="~/.config/${PRODUCT}/pilot/directory.env"
fi

echo "Type each directory range (IPv4 CIDR or single address) and press Enter; nothing is shown. An empty line ends."
ranges=()
n=0
while [ "${#ranges[@]}" -lt 8 ]; do
  n=$((n + 1))
  value=""
  # read fails at the end of input; a last line without a newline still counts
  IFS= read -rs -p "range ${n}: " value || true
  # a line pasted from a Windows terminal ends in CR; a CR-only line is an empty line
  value="${value%$'\r'}"
  if [ -t 0 ]; then
    echo >&2
  fi
  if [ -z "${value}" ]; then
    break
  fi
  if printf '%s\n' ${ranges[@]+"${ranges[@]}"} "${value}" | python3 -B "${CHECKER}" --check-next; then
    ranges+=("${value}")
  else
    echo "range ${n} not taken; type it again or end with an empty line" >&2
  fi
  value=""
done
if [ "${#ranges[@]}" -eq 8 ]; then
  echo "8 ranges taken, the most the policy holds"
fi

if [ "${#ranges[@]}" -eq 0 ]; then
  echo "no range accepted; ${SHOWN} left as it was" >&2
  exit 1
fi
if ! printf '%s\n' "${ranges[@]}" | python3 -B "${CHECKER}" "${WRITE_ARGS[@]}"; then
  echo "nothing written; ${SHOWN} left as it was" >&2
  exit 1
fi
ranges=()
echo "written: ${SHOWN}; next, the orchestrator renders and applies the control phase's NetworkPolicies (step 14.5)"
