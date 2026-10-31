#!/usr/bin/env bash
# PRODUCT OWNER ONLY (PILOT_RUNBOOK.md step 10; PO answer to the PR 33 review question): the orchestrating agent never
# runs this script and never reads its file. It refuses to run without an interactive terminal on both stdin and
# stdout, so a piped or scripted run (the way an agent runs commands) stops before anything is read.
#
# Copies the break-glass account's initial password to an owner-only file on the HOST-A terminal, without printing it.
# The control plane generates the password itself at its first start (the code's rule, BreakGlassAccounts: generated,
# stored as a BCrypt hash, written once owner-only to RWSAFE_BREAK_GLASS_PASSWORD_FILE on the PVC
# <product>-control-identity), so no script can choose it; this one moves the content from the pod to
#   ~/.config/<product>/pilot/break-glass-initial-password   (both directories 0700, the file 0600)
# through a pipe into that file, then removes the copy in the pod's PVC (PR 33 review D-04), so exactly one copy is
# left, in your home. The account exists in the database from then on; the control plane does not write the file again.
# The account name is `breakglass`. Read the file yourself (`cat` it in your own terminal); never paste it anywhere.
#
# Usage: tools/pilot/fetch_break_glass.sh
# Environment: PRODUCT (one-command override of product.env), KUBECTL (default `kubectl`)
# Exit: 0 written (or already there), 1 failed, 2 not run by the PO in a terminal
set -euo pipefail
umask 077

# shellcheck source=tools/pilot/common.sh
. "$(dirname "$0")/common.sh"

if [ ! -t 0 ] || [ ! -t 1 ]; then
  echo "step 10 is the Product Owner's only: run it yourself in your own terminal (PILOT_RUNBOOK.md step 10)" >&2
  exit 2
fi

BASE="${HOME}/.config/${PRODUCT}"
DIR="${BASE}/pilot"
DEST="${DIR}/break-glass-initial-password"
# shellcheck disable=SC2088  # printed literally: the path without the account name in $HOME
SHOWN="~/.config/${PRODUCT}/pilot/break-glass-initial-password"
SOURCE_FILE="/var/lib/rwsafe/identity/break-glass-initial-password"

mkdir -p "${DIR}"
chmod 0700 "${BASE}" "${DIR}"
if [ -s "${DEST}" ]; then
  echo "already there: ${SHOWN} (left as it is)"
  exit 0
fi

TMP="$(mktemp "${DIR}/.incoming.XXXXXX")"
trap 'shred -u "${TMP}" 2>/dev/null || rm -f "${TMP}"' EXIT
trap 'exit 130' INT TERM HUP
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

# The copy in the pod's PVC is no longer needed (the file is never read back by the application). The inner script is
# single-quoted on purpose: it receives the path as its $1.
# shellcheck disable=SC2016
if k -n "${NS}" exec "deploy/${PRODUCT}-control" -c control -- \
     sh -c 'shred -u "$1" 2>/dev/null || rm -f "$1"' _ "${SOURCE_FILE}" >/dev/null 2>&1; then
  echo "removed the copy in the control plane's PVC"
else
  echo "WARNING: the copy in the control plane's PVC could not be removed; step 18 deletes it with the namespace" >&2
fi
