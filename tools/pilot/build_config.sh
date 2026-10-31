#!/usr/bin/env bash
# Creates or updates the image build's three uncommitted ConfigMaps in "<product>-build" (PILOT_RUNBOOK.md step 3),
# from deploy/rwsafe/contracts/runtime-contracts.json section "build":
#
#   <product>-build-config  image-tag            the short commit id of the checkout (`git rev-parse --short=12 HEAD`)
#   <product>-build-ca      ca-certificates.crt  the host's own CA bundle (public CA material)
#   <product>-build-proxy   HTTP_PROXY, HTTPS_PROXY, NO_PROXY, GRADLE_OPTS  from the operator's store, an env file
#
# The proxy file (default ~/.config/<product>/build-proxy.env, mode 0600 or stricter) is checked before anything is
# stored, and refused (PR 33 review D-03) when: a key is missing, unknown or repeated; it is readable by group or others;
# a proxy URL carries credentials (userinfo `user:pass@`), is not http(s), or has a path; GRADLE_OPTS holds anything but
# -Dhttp(s).proxyHost, -Dhttp(s).proxyPort and -Dhttp.nonProxyHosts (no proxyUser, no proxyPassword); NO_PROXY lacks
# the in-cluster registry while a proxy is set. On a network without a proxy all four keys are present and empty. No
# value is ever printed: the check reports rule names only, and every kubectl output is discarded (common.sh
# `labelled`). Re-running it updates the three ConfigMaps (a new commit, a new tag).
#
# Usage: tools/pilot/build_config.sh [--check]
#   --check  read-only: validates the proxy file and the CA bundle, stores nothing
# Environment: PRODUCT, KUBECTL (common.sh), BUILD_PROXY_ENV (the proxy file), CA_BUNDLE (default
#              /etc/ssl/certs/ca-certificates.crt)
# Exit: 0 stored (or checked), 1 refused or failed, 2 usage or prerequisites
set -euo pipefail
umask 077

# shellcheck source=tools/pilot/common.sh
. "$(dirname "$0")/common.sh"

CHECK=0
case "${1:-}" in
  "") ;;
  --check) CHECK=1 ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

BNS="${PRODUCT}-build"
PROXY_FILE="${BUILD_PROXY_ENV:-${HOME}/.config/${PRODUCT}/build-proxy.env}"
CA_BUNDLE="${CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"

if [ ! -s "${CA_BUNDLE}" ] || ! grep -q -- '-----BEGIN CERTIFICATE-----' "${CA_BUNDLE}"; then
  echo "the CA bundle is missing or holds no certificate" >&2
  exit 1
fi

python3 -B "${PILOT_REPO}/tools/pilot/proxy_settings.py" "${PROXY_FILE}" "${PILOT_REPO}/deploy/rwsafe/contracts/runtime-contracts.json" || exit 1

if [ "${CHECK}" = 1 ]; then
  echo "check passed: proxy settings and CA bundle are usable; nothing stored"
  exit 0
fi

if ! k get namespace "${BNS}" >/dev/null 2>&1; then
  echo "namespace ${BNS} does not exist: apply the isolation objects first (PILOT_RUNBOOK.md step 2)" >&2
  exit 1
fi
# A checkout has .git; a copy made with `git archive` (the host cannot reach GitHub) carries the commit id in .pilot-commit.
if [ -d "${PILOT_REPO}/.git" ]; then
  TAG="$(git -C "${PILOT_REPO}" rev-parse --short=12 HEAD)"
elif [ -f "${PILOT_REPO}/.pilot-commit" ]; then
  TAG="$(head -c 12 "${PILOT_REPO}/.pilot-commit")"
else
  echo "refused: neither a git checkout nor a .pilot-commit file" >&2; exit 2
fi
case "${TAG}" in
  *[!0-9a-f]*|'') echo "refused: the commit id is not 12 hex characters" >&2; exit 2 ;;
esac
[ "${#TAG}" -eq 12 ] || { echo "refused: the commit id is not 12 hex characters" >&2; exit 2; }

labelled apply "${BNS}" configmap "${PRODUCT}-build-config" --from-literal=image-tag="${TAG}" \
  || { echo "storing ${PRODUCT}-build-config failed (kubectl output withheld)" >&2; exit 1; }
echo "stored configmap ${PRODUCT}-build-config (image-tag ${TAG})"
labelled apply "${BNS}" configmap "${PRODUCT}-build-ca" --from-file=ca-certificates.crt="${CA_BUNDLE}" \
  || { echo "storing ${PRODUCT}-build-ca failed (kubectl output withheld)" >&2; exit 1; }
echo "stored configmap ${PRODUCT}-build-ca"
labelled apply "${BNS}" configmap "${PRODUCT}-build-proxy" --from-env-file="${PROXY_FILE}" \
  || { echo "storing ${PRODUCT}-build-proxy failed (kubectl output withheld)" >&2; exit 1; }
echo "stored configmap ${PRODUCT}-build-proxy (values not shown)"
