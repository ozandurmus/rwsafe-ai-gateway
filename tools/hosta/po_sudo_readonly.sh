#!/usr/bin/env bash
# Root-only READ-ONLY listings on HOST-A, run by the Product Owner in a terminal (PO rule 2026-10-30: the agent never holds
# sudo; for a listing the agent opens a terminal and the PO authenticates). One ssh session with a tty: `sudo -v` asks the
# password once, every later sudo in the same session reuses it. Nothing is written, changed or deleted on the host.
# Every byte that comes back is masked locally (tools/hosta/mask.sh) before it reaches the screen or the output file.
# The PO types the ssh password of their account first, then the sudo password once.
# `-q` keeps ssh's own messages ("Connection to <address> closed") off the terminal: they bypass the mask pipe.
#
#   tools/hosta/po_sudo_readonly.sh <output-file>
set -u
OUT=${1:?usage: po_sudo_readonly.sh <output-file>}
HOST=$(head -1 "$HOME/.config/nexus/hosta" 2>/dev/null)
[ -n "$HOST" ] || { echo "write user@host to ~/.config/nexus/hosta first" >&2; exit 64; }
# The agent's account has no sudo. The PO's own sudo-capable account (password login) is local configuration, never a
# repository literal: first line of ~/.config/rwsafe/hosta_sudo_user, or RWSAFE_HOSTA_SUDO_USER.
SUDO_USER_NAME=${RWSAFE_HOSTA_SUDO_USER:-$(head -1 "$HOME/.config/rwsafe/hosta_sudo_user" 2>/dev/null)}
[ -n "$SUDO_USER_NAME" ] || { echo "write the PO's sudo-capable account name to ~/.config/rwsafe/hosta_sudo_user first" >&2; exit 64; }
HOST="$SUDO_USER_NAME@${HOST#*@}"
DIR=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$(dirname "$OUT")"
REMOTE='sudo -v -p "[HOST-A sudo] password (typing is hidden), then Enter:
" && {
H=$(hostname); S=$(hostname -s); nm() { sed -e "s/$H/<node>/g" -e "s/$S/<node>/g"; }
echo "===== nft ruleset ====="; sudo nft list ruleset 2>&1 | nm;
echo "===== sshd effective (selected keys) ====="; sudo sshd -T 2>/dev/null | grep -iE "^(allowtcpforwarding|allowagentforwarding|x11forwarding|allowusers|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|maxauthtries|clientaliveinterval|clientalivecountmax|port|listenaddress|banner) " | sed -E "s/^(allowusers) .*/\1 <count=$(sudo sshd -T 2>/dev/null | grep -ic allowusers)>/";
echo "===== k3s config.yaml ====="; sudo cat /etc/rancher/k3s/config.yaml 2>&1 | nm;
echo "===== k3s config.yaml.d ====="; sudo sh -c "ls /etc/rancher/k3s/config.yaml.d/ 2>/dev/null && cat /etc/rancher/k3s/config.yaml.d/* 2>/dev/null" | nm;
echo "===== k3s registries.yaml (keys only) ====="; sudo sed -E "s#(https?://)[^\"'"'"' ]+#\1<endpoint>#g" /etc/rancher/k3s/registries.yaml 2>&1 | nm;
echo "===== k3s server manifests dir ====="; sudo ls -la /var/lib/rancher/k3s/server/manifests/ 2>&1;
echo "===== k3s secrets-encrypt status ====="; sudo k3s secrets-encrypt status 2>&1 | nm;
echo "===== k3s service env (keys only) ====="; sudo sed -E "s/=.*/=<value>/" /etc/systemd/system/k3s.service.env 2>&1;
echo "===== /etc/nexus listing ====="; sudo ls -la /etc/nexus/ 2>&1;
echo "===== disk usage of root-owned paths ====="; sudo du -sh /var/lib/rancher/k3s/storage/* /var/lib/rancher/k3s/agent/containerd /var/backups/nexus /var/lib/nexus-security /var/log 2>&1 | nm;
echo "===== listening sockets with processes (all users) ====="; sudo ss -ltnpH 2>&1; sudo ss -lunpH 2>&1;
echo "===== containerd registry mirrors (keys only) ====="; sudo sh -c "ls /var/lib/rancher/k3s/agent/etc/containerd/ 2>/dev/null; grep -E \"^\\s*\\[|server|capabilities\" /var/lib/rancher/k3s/agent/etc/containerd/certs.d/*/hosts.toml 2>/dev/null" | sed -E "s#(https?://)[^\" ]+#\1<endpoint>#g" | nm;
echo "===== done =====";
}'
# Line-buffered pipe (BSD sed -l, grep --line-buffered): the sudo prompt must reach the screen before the PO types.
ssh -q -t -o ConnectTimeout=15 -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no "$HOST" "$REMOTE" | sed -l -e 's/\r$//' | grep --line-buffered -vE 'Authorized access only|Yalnizca yetkili|^\*{10,}$' | MASK_SED_FLAGS=-l "$DIR/mask.sh" | tee "$OUT"
echo
echo "masked output written: $OUT ($(wc -l < "$OUT" | tr -d ' ') lines)"
