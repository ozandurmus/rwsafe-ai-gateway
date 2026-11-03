#!/usr/bin/env bash
# PRODUCT OWNER (PILOT_RUNBOOK.md step 11.5): the ProxySG addresses that may open ICAP (TCP 1344) on the product's ICAP
# pods, typed on the HOST-A terminal only: the same addresses as the host firewall step (step 11). They are a real
# network identifier, so they are never committed, pasted into chat or passed as a command argument (AGENTS.md 4.2, 8).
#
# Reads each address with `read -rs` (nothing is echoed; a trailing carriage return is dropped): one private IPv4
# address, no prefix; an empty line ends the list, at most 8. Each address is checked as it is typed
# (tools/pilot/icap_clients.py: IPv4, private (RFC 1918), outside loopback, link-local, multicast, reserved, broadcast
# and the cluster's pod and Service ranges, no repeat); a refused address is named by its number and rule only, and may
# be typed again. Then
#   ~/.config/<product>/pilot/icap-clients.env   (both directories 0700 and never symbolic links, the file 0600)
# is replaced as a whole with one `PROXY_ADDR=` line per address, and only the count is printed. The values travel only
# through pipes to icap_clients.py (shell builtins, never a process argument). Run it as the host account that renders
# (the orchestrator's account): tools/pilot/render.py reads the file from that account's home. Running it again replaces
# the file; deleting the file and rendering again admits no proxy.
#
# Usage: tools/pilot/icap_clients.sh
# Environment: PRODUCT (one-command override of product.env); ICAP_CLIENTS_ENV (another file, for tests)
# Exit: 0 written, 1 nothing written (no accepted address) or failed, 2 usage
set -euo pipefail
umask 077

# shellcheck source=tools/pilot/common.sh
. "$(dirname "$0")/common.sh"

if [ "$#" -ne 0 ]; then
  echo "usage: $0 (no arguments; the addresses are typed, never given as arguments)" >&2
  exit 2
fi
if [ "$(id -u)" = 0 ]; then
  echo "run as the host user, never as root (AGENTS.md section 8)" >&2
  exit 2
fi

CHECKER="${PILOT_REPO}/tools/pilot/icap_clients.py"
if [ -n "${ICAP_CLIENTS_ENV:-}" ]; then
  DEST="${ICAP_CLIENTS_ENV}"
  # shellcheck disable=SC2088  # printed literally
  SHOWN="the file named by ICAP_CLIENTS_ENV"
else
  BASE="${HOME}/.config/${PRODUCT}"
  for dir in "${HOME}/.config" "${BASE}" "${BASE}/pilot"; do
    if [ -L "${dir}" ]; then
      echo "refused: a configuration directory is a symbolic link; nothing written" >&2
      exit 1
    fi
  done
  mkdir -p "${BASE}/pilot"
  chmod 0700 "${BASE}" "${BASE}/pilot"
  DEST="${BASE}/pilot/icap-clients.env"
  # shellcheck disable=SC2088  # printed literally: the path without the account name in $HOME
  SHOWN="~/.config/${PRODUCT}/pilot/icap-clients.env"
fi

echo "Type each ProxySG address (one IPv4 address, no prefix) and press Enter; nothing is shown. An empty line ends."
addresses=()
n=0
while [ "${#addresses[@]}" -lt 8 ]; do
  n=$((n + 1))
  value=""
  # read fails at the end of input; a last line without a newline still counts
  IFS= read -rs -p "address ${n}: " value || true
  value="${value%$'\r'}"
  if [ -t 0 ]; then
    echo >&2
  fi
  if [ -z "${value}" ]; then
    break
  fi
  if printf '%s\n' ${addresses[@]+"${addresses[@]}"} "${value}" | python3 -B "${CHECKER}" --check-next; then
    addresses+=("${value}")
  else
    echo "address ${n} not taken; type it again or end with an empty line" >&2
  fi
  value=""
done
if [ "${#addresses[@]}" -eq 8 ]; then
  echo "8 addresses taken, the most the policy holds"
fi

if [ "${#addresses[@]}" -eq 0 ]; then
  echo "no address accepted; ${SHOWN} left as it was" >&2
  exit 1
fi
if ! printf '%s\n' "${addresses[@]}" | python3 -B "${CHECKER}" --write "${DEST}"; then
  echo "nothing written; ${SHOWN} left as it was" >&2
  exit 1
fi
addresses=()
echo "written: ${SHOWN}; next, the orchestrator renders and applies the ICAP phase's NetworkPolicies (step 11.5)"
