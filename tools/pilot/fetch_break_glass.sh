#!/usr/bin/env bash
# Copies the break-glass account's initial password to an owner-only file on the HOST-A terminal (PILOT_RUNBOOK.md
# step 10), without printing it. The control plane generates the password itself at its first start (it is the code's
# rule, BreakGlassAccounts: generated, stored as a BCrypt hash, written once owner-only to
# RWSAFE_BREAK_GLASS_PASSWORD_FILE on the PVC <product>-control-identity), so no script can choose it; this one only
# moves the file's content from the pod to
#   ~/.config/<product>/pilot/break-glass-initial-password   (directory 0700, file 0600; root-only when run as root)
# through a pipe into that file. The account name is `breakglass`. Read the file yourself (`cat` it in your own
# terminal); never paste it into a chat or a file in the repository.
#
# Usage: tools/pilot/fetch_break_glass.sh
# Environment: PRODUCT (one-command override of product.env), KUBECTL (default `kubectl`)
# Exit: 0 written (or already there), 1 failed
set -euo pipefail
umask 077

# shellcheck source=tools/pilot/common.sh
. "$(dirname "$0")/common.sh"

DIR="${HOME}/.config/${PRODUCT}/pilot"
DEST="${DIR}/break-glass-initial-password"
# shellcheck disable=SC2088  # printed literally: the path without the account name in $HOME
SHOWN="~/.config/${PRODUCT}/pilot/break-glass-initial-password"
SOURCE_FILE="/var/lib/rwsafe/identity/break-glass-initial-password"

mkdir -p "${DIR}"
chmod 0700 "${DIR}"
if [ -s "${DEST}" ]; then
  echo "already there: ${SHOWN} (left as it is)"
  exit 0
fi

TMP="$(mktemp "${DIR}/.incoming.XXXXXX")"
trap 'shred -u "${TMP}" 2>/dev/null || rm -f "${TMP}"' EXIT
if ! k -n "${NS}" exec "deploy/${PRODUCT}-control" -c control -- cat "${SOURCE_FILE}" > "${TMP}" 2>/dev/null; then
  echo "could not read the file in the control plane pod: is it ready (check_pilot.sh), and is this its first start?" >&2
  echo "If the account was created earlier and the file is gone, see PILOT_RUNBOOK.md step 10 (reset)." >&2
  exit 1
fi
if [ ! -s "${TMP}" ]; then
  echo "the file in the pod is empty; nothing written" >&2
  exit 1
fi
chmod 0600 "${TMP}"
mv "${TMP}" "${DEST}"
trap - EXIT
echo "written: ${SHOWN} (mode 0600); sign in as breakglass with it; no value was printed"
