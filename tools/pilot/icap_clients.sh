#!/usr/bin/env bash
# PRODUCT OWNER (PILOT_RUNBOOK.md step 11.5): the ProxySG addresses that may open ICAP (TCP 1344) on the product's ICAP
# pods, typed on the HOST-A terminal only: the same addresses as the host firewall step (step 11; today the one test
# proxy, PO 2026-11-03). They are a real network identifier, so they are never committed, pasted into chat or passed
# as a command argument (AGENTS.md 4.2, 8).
#
# Reads one address with `read -rs` (nothing is echoed; a trailing carriage return is dropped), checks it
# (tools/pilot/icap_clients.py: one IPv4 address, no prefix, private (RFC 1918), outside loopback, link-local,
# multicast, reserved, broadcast and the cluster's pod and Service ranges, no repeat; a refused address is named by its
# number and rule only and is asked again), then asks "Baska adres eklensin mi? (y/n)": y asks the next address, n
# writes what was entered (at least 1, at most 8). Then
#   ~/.config/<product>/pilot/icap-clients.env   (both directories 0700 and never symbolic links, the file 0600)
# is replaced as a whole with one `PROXY_ADDR=` line per address, and only the count is printed. The values travel only
# through pipes to icap_clients.py (shell builtins, never a process argument), and neither does the file's path. Run it
# as the host account that renders (the orchestrator's account): tools/pilot/render.py reads the file from that
# account's home. Running it again replaces the file; deleting the file and rendering again admits no proxy.
#
# Usage: tools/pilot/icap_clients.sh
# Environment: PRODUCT (one-command override of product.env); ICAP_CLIENTS_ENV (another file, for tests)
# Exit: 0 written, 1 nothing written (input ended or failed), 2 usage
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
# The file's path never becomes a process argument (it carries the account name in $HOME): icap_clients.py takes the
# product's default path itself; ICAP_CLIENTS_ENV (tests only) names another.
WRITE_ARGS=(--write --product "${PRODUCT}")
if [ -n "${ICAP_CLIENTS_ENV:-}" ]; then
  WRITE_ARGS=(--write "${ICAP_CLIENTS_ENV}")
  SHOWN="the file named by ICAP_CLIENTS_ENV"
else
  BASE="${HOME}/.config/${PRODUCT}"
  for d in "${HOME}/.config" "${BASE}" "${BASE}/pilot" "${BASE}/pilot/icap-clients.env"; do
    if [ -L "${d}" ]; then
      echo "refused: ~/.config/${PRODUCT}/... holds a symbolic link; nothing written" >&2
      exit 1
    fi
  done
  mkdir -p "${BASE}/pilot"
  chmod 0700 "${BASE}" "${BASE}/pilot"
  # shellcheck disable=SC2088  # printed literally: the path without the account name in $HOME
  SHOWN="~/.config/${PRODUCT}/pilot/icap-clients.env"
fi

ended() {
  echo "input ended; nothing written, ${SHOWN} left as it was" >&2
  exit 1
}

echo "Vekil adresini yazip Enter'a basin (tek IPv4 adresi; yazdiginiz gorunmez)."
addresses=()
n=0
while [ "${#addresses[@]}" -lt 8 ]; do
  n=$((n + 1))
  value=""
  # read fails at the end of input; a last line without a newline still counts
  if ! IFS= read -rs -p "adres ${n}: " value && [ -z "${value}" ]; then
    ended
  fi
  value="${value%$'\r'}"
  if [ -t 0 ]; then
    echo >&2
  fi
  if ! printf '%s\n' ${addresses[@]+"${addresses[@]}"} "${value}" | python3 -B "${CHECKER}" --check-next; then
    echo "adres ${n} alinmadi; yeniden yazin" >&2
    value=""
    continue
  fi
  addresses+=("${value}")
  value=""
  if [ "${#addresses[@]}" -ge 8 ]; then
    echo "8 adres alindi, en fazla bu kadar"
    break
  fi
  answer=""
  while :; do
    if ! IFS= read -r -p "Baska adres eklensin mi? (y/n) " answer && [ -z "${answer}" ]; then
      ended
    fi
    answer="${answer%$'\r'}"
    case "${answer}" in
      y|Y|n|N) break ;;
      *) echo "y ya da n yazin" >&2 ;;
    esac
  done
  case "${answer}" in
    n|N) break ;;
  esac
done

if ! printf '%s\n' "${addresses[@]}" | python3 -B "${CHECKER}" "${WRITE_ARGS[@]}"; then
  echo "nothing written; ${SHOWN} left as it was" >&2
  exit 1
fi
addresses=()
echo "written: ${SHOWN}; next, the orchestrator renders and applies the ICAP phase's NetworkPolicies (step 11.5)"
