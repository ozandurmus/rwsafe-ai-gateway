#!/usr/bin/env bash
# The admin UI's TLS certificate (docs/operations/PILOT_RUNBOOK.md step 14), run on the HOST-A terminal as the host user
# (never root, never sudo) by the orchestrating agent once the PO confirms the step, or by the PO:
#
#   1. a small private CA for the pilot, made once: an ECDSA P-256 key and a self-signed certificate valid for 10 years,
#      name-constrained to the one admin host name, so the CA can sign nothing else even if its key were taken. The key
#      lives only in ~/.config/<product>/admin-ca/ca.key (mode 0600, directory 0700) on the host; it never enters the
#      cluster, a command argument or the terminal. The certificate ~/.config/<product>/admin-ca/ca.crt is public: the
#      PO copies it to his computer and trusts it there.
#   2. a leaf certificate for `ui.<product>.local` only (subjectAltName DNS only, 825 days, serverAuth, ECDSA P-256),
#      signed by that CA, and the TLS Secret `<product>-admin-tls` in `<product>` made from the leaf certificate and key
#      (`kubectl create secret tls` from files, labelled part-of the product; every kubectl output discarded). Traefik
#      serves it for the Ingress `<product>-admin` (deploy/rwsafe/overlays/pilot/70-admin-ingress.yaml).
#
# Both keys use the named curve (`ec_param_enc:named_curve`): explicit curve parameters, which some openssl builds write
# by default, are refused by Go's crypto/x509 (Traefik) and by browsers (tools/pilot/test_admin_tls.py).
#
# The leaf key and certificate are made in a `mktemp -d` directory (umask 077) and shredded on exit, also on an
# interrupt. Idempotent: when the Secret exists it is left as it is, unless --renew, which issues a new leaf from the
# same CA and replaces the Secret (the PO imports nothing again). A missing CA is made anew only with --renew when the
# Secret exists (the PO must then import the new CA certificate); one of ca.key and ca.crt without the other is refused.
#
# Prints only status lines, the CA certificate's path (as ~/...) and its SHA-256 fingerprint, which the PO compares on
# his computer before he trusts it. Never a key, a certificate body or an address.
#
# Usage: tools/pilot/admin_tls.sh [--renew]
# Environment: PRODUCT (one-command override of product.env), KUBECTL (default `kubectl`)
# Exit: 0 done, 1 refused or failed, 2 usage or prerequisites
set -euo pipefail
umask 077

# shellcheck source=tools/pilot/common.sh
. "$(dirname "$0")/common.sh"

RENEW=0
case "${1:-}" in
  "") ;;
  --renew) RENEW=1 ;;
  *) echo "usage: $0 [--renew]" >&2; exit 2 ;;
esac
if [ "$(id -u)" = 0 ]; then
  echo "run as the host user, never as root (AGENTS.md section 8)" >&2
  exit 2
fi
for tool in openssl python3 shred; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "missing tool: ${tool}" >&2; exit 2; }
done
command -v "${KUBECTL[0]}" >/dev/null 2>&1 || { echo "missing tool: ${KUBECTL[0]}" >&2; exit 2; }

HOST="ui.${PRODUCT}.local"
TLS_OBJECT="${PRODUCT}-admin-tls"
CA_DIR_REL=".config/${PRODUCT}/admin-ca"
CA_DIR="${HOME}/${CA_DIR_REL}"
CA_KEY="${CA_DIR}/ca.key"
CA_CERT="${CA_DIR}/ca.crt"

# The Secret and its keys must be in the runtime contract (committed `rwsafe` spelling).
python3 -B - "${PILOT_REPO}/deploy/rwsafe/contracts/runtime-contracts.json" <<'PY' || exit 2
import json
import sys

keys = (json.load(open(sys.argv[1], encoding="utf-8")).get("secrets", {}).get("rwsafe-admin-tls") or {}).get("keys") or []
if sorted(keys) != ["tls.crt", "tls.key"]:
    print("secret rwsafe-admin-tls with keys tls.crt, tls.key is not in the runtime contract", file=sys.stderr)
    sys.exit(1)
PY

if ! k get namespace "${NS}" >/dev/null 2>&1; then
  echo "namespace ${NS} does not exist: apply the isolation objects first (PILOT_RUNBOOK.md step 2)" >&2
  exit 1
fi

WORK="$(mktemp -d)"
cleanup() {
  find "${WORK}" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "${WORK}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

fingerprint() {
  echo "CA certificate (public; copy it to your computer): ~/${CA_DIR_REL}/ca.crt"
  echo "CA SHA-256 fingerprint: $(openssl x509 -in "${CA_CERT}" -noout -fingerprint -sha256 2>/dev/null | sed 's/^[^=]*=//')"
}

secret_exists=0
if k -n "${NS}" get secret "${TLS_OBJECT}" >/dev/null 2>&1; then
  secret_exists=1
fi
if [ "${secret_exists}" = 1 ] && [ "${RENEW}" = 0 ]; then
  if [ ! -f "${CA_CERT}" ]; then
    echo "secret ${TLS_OBJECT} exists but the CA files under ~/${CA_DIR_REL}/ are missing: run with --renew for a new CA and leaf (the PO then imports the new CA certificate)" >&2
    exit 1
  fi
  echo "exists, left as it is: secret ${TLS_OBJECT} (--renew issues a new leaf from the same CA)"
  fingerprint
  exit 0
fi

# 1. The CA, once.
if [ -f "${CA_KEY}" ] && [ -f "${CA_CERT}" ]; then
  ca_pub="$(openssl pkey -in "${CA_KEY}" -pubout 2>/dev/null | openssl sha256 2>/dev/null)"
  cert_pub="$(openssl x509 -in "${CA_CERT}" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null)"
  if [ -z "${ca_pub}" ] || [ "${ca_pub}" != "${cert_pub}" ]; then
    echo "~/${CA_DIR_REL}/ca.key and ca.crt do not belong together; move the directory aside and run again" >&2
    exit 1
  fi
  echo "CA exists, reused: ~/${CA_DIR_REL}/"
elif [ -f "${CA_KEY}" ] || [ -f "${CA_CERT}" ]; then
  echo "only one of ~/${CA_DIR_REL}/ca.key and ca.crt exists; move the directory aside and run again" >&2
  exit 1
else
  mkdir -p "${CA_DIR}"
  chmod 0700 "${HOME}/.config/${PRODUCT}" "${CA_DIR}"
  cat > "${WORK}/ca.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
x509_extensions = ca_ext
[dn]
CN = ${PRODUCT} pilot admin CA
[ca_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
nameConstraints = critical, permitted;DNS:${HOST}, excluded;IP:0.0.0.0/0.0.0.0, excluded;IP:::/0:0:0:0:0:0:0:0
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
EOF
  if ! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out "${WORK}/ca.key" >/dev/null 2>&1 \
      || ! openssl req -new -x509 -config "${WORK}/ca.cnf" -key "${WORK}/ca.key" -sha256 -days 3650 \
           -set_serial "0x$(openssl rand -hex 16)" -out "${WORK}/ca.crt" >/dev/null 2>&1; then
    echo "openssl could not make the CA" >&2
    exit 2
  fi
  # umask 077: the key file is created 0600 before it holds anything; the certificate (public) is then made 0644.
  cat "${WORK}/ca.key" > "${CA_KEY}"
  chmod 0600 "${CA_KEY}"
  cat "${WORK}/ca.crt" > "${CA_CERT}"
  chmod 0644 "${CA_CERT}"
  echo "CA created: ~/${CA_DIR_REL}/ (key mode 0600, never in the cluster); the PO imports its certificate"
fi

# 2. The leaf for the admin host only.
cat > "${WORK}/leaf.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = ${HOST}
[leaf_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:${HOST}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
if ! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out "${WORK}/tls.key" >/dev/null 2>&1 \
    || ! openssl req -new -config "${WORK}/leaf.cnf" -key "${WORK}/tls.key" -out "${WORK}/leaf.csr" >/dev/null 2>&1 \
    || ! openssl x509 -req -in "${WORK}/leaf.csr" -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
         -set_serial "0x$(openssl rand -hex 16)" -days 825 -sha256 -extfile "${WORK}/leaf.cnf" \
         -extensions leaf_ext -out "${WORK}/tls.crt" >/dev/null 2>&1; then
  echo "openssl could not issue the leaf certificate" >&2
  exit 2
fi
if ! openssl verify -CAfile "${CA_CERT}" "${WORK}/tls.crt" >/dev/null 2>&1; then
  echo "the leaf certificate does not verify against the CA; nothing was stored" >&2
  exit 1
fi

if [ "${secret_exists}" = 1 ]; then
  mode=apply
else
  mode=create
fi
if ! labelled "${mode}" "${NS}" secret tls "${TLS_OBJECT}" --cert="${WORK}/tls.crt" --key="${WORK}/tls.key"; then
  echo "storing secret ${TLS_OBJECT} failed (kubectl output withheld; check access with: kubectl -n ${NS} auth can-i create secrets)" >&2
  exit 1
fi
if [ "${mode}" = apply ]; then
  echo "renewed secret ${TLS_OBJECT} (leaf for ${HOST}, 825 days)"
else
  echo "created secret ${TLS_OBJECT} (leaf for ${HOST}, 825 days)"
fi
fingerprint
echo "done; no key was printed"
