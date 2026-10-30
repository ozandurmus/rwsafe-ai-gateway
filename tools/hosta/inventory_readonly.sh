#!/usr/bin/env bash
# Read-only HOST-A inventory for the rwsafe port, capacity and isolation plan (kickoff brief section 4, rules 3 and 4A).
#
#   tools/hosta/inventory_readonly.sh <output-file>
#
# - The host is local configuration, never a repository literal: the first line of ~/.config/nexus/hosta (user@address).
# - Runs tools/hosta/remote_inventory.sh on the host through `bash -s`; nothing is copied to or changed on the host.
# - Every byte that comes back passes through tools/hosta/mask.sh before it is written; the agent reads only the file.
# - BatchMode: no interactive prompt. Commands that need root are NOT here; see po_sudo_readonly.sh.
set -u
OUT=${1:?usage: inventory_readonly.sh <output-file>}
HOST=$(head -1 "$HOME/.config/nexus/hosta" 2>/dev/null)
[ -n "$HOST" ] || { echo "write user@host to ~/.config/nexus/hosta first" >&2; exit 64; }
DIR=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$(dirname "$OUT")"
ssh -o ConnectTimeout=15 -o BatchMode=yes -i "$HOME/.ssh/id_ed25519" "$HOST" bash -s < "$DIR/remote_inventory.sh" 2>&1 \
  | tr -d '\r' | grep -vE 'Authorized access only|Yalnizca yetkili|^\*{10,}$' | "$DIR/mask.sh" > "$OUT"
rc=${PIPESTATUS[0]}
echo "masked inventory written: $OUT ($(wc -l < "$OUT" | tr -d ' ') lines, ssh exit $rc)"
