#!/usr/bin/env bash
# Creates every Secret and uncommitted ConfigMap the pilot needs (docs/operations/PILOT_RUNBOOK.md step 7), run on the
# HOST-A terminal by the Product Owner or, once he confirms the step, by the orchestrating agent. Names and keys come
# from deploy/rwsafe/contracts/runtime-contracts.json (checked here), under the product name (deploy/rwsafe/product.env):
#
#   Secret    <product>-snapshot-signing-key   rwsafe-snapshot-1.pem        Ed25519 PKCS#8 signing key (openssl genpkey)
#   ConfigMap <product>-snapshot-public-keys   rwsafe-snapshot-1.pem        its public key (SubjectPublicKeyInfo PEM)
#   Secret    <product>-privacy-hmac-key       key                          32 bytes from /dev/urandom
#   Secret    <product>-db-credentials         spring.datasource.password   48 hex characters (openssl rand)
#                                              rwsafe.migration.password    48 hex characters (openssl rand)
#   ConfigMap <product>-estate                 estate-dictionary.txt        ONE synthetic placeholder term (see below)
#
# Not created, because the pilot does not use them: the ICAP TLS Secret (plain ICAP, H-2), the directory bind Secret
# (break-glass sign-in only), the SIEM objects, the capture key, the end-user notice values.
#
# The estate dictionary: an empty or comment-only dictionary is refused by design (masked views answer 503, PR 26 review
# D-07), so it is created with one synthetic placeholder term. Replace it with the estate's real terms before anyone
# uses the masked role (runbook step 7); the pilot's own checks do not need it.
#
# Values are generated in a `mktemp -d` directory (mode 0700, umask 077), passed to kubectl only as files
# (`--from-file`), never as an argument, and shredded on exit (also on an interrupt). Nothing prints a value: every
# kubectl and openssl output, stdout and stderr, is discarded and the script prints its own status line (PR 33 review
# D-03). Each object is created already labelled part-of the product (common.sh `labelled`, PR 33 review D-07). Idempotent: an object that exists
# is left as it is (the signing key and its public key only as a pair; one without the other is refused). The database
# passwords are read by the database only at its first initialisation, so never recreate rwsafe-db-credentials while the
# database PVC exists.
#
# Usage: tools/pilot/bootstrap_secrets.sh [--plan]
#   --plan  read-only: says what exists and what would be created, changes nothing
# Environment: PRODUCT (one-command override of product.env), KUBECTL (default `kubectl`)
# Exit: 0 done (or plan printed), 1 refused or failed, 2 usage or prerequisites
set -euo pipefail
umask 077

# shellcheck source=tools/pilot/common.sh
. "$(dirname "$0")/common.sh"

PLAN=0
case "${1:-}" in
  "") ;;
  --plan) PLAN=1 ;;
  *) echo "usage: $0 [--plan]" >&2; exit 2 ;;
esac

for tool in openssl python3 shred head; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "missing tool: ${tool}" >&2; exit 2; }
done
command -v "${KUBECTL[0]}" >/dev/null 2>&1 || { echo "missing tool: ${KUBECTL[0]}" >&2; exit 2; }

CONTRACT="${PILOT_REPO}/deploy/rwsafe/contracts/runtime-contracts.json"
# Every object and key created below must be in the contract (names in the committed `rwsafe` spelling).
python3 -B - "${CONTRACT}" <<'PY' || exit 2
import json
import sys

contract = json.load(open(sys.argv[1], encoding="utf-8"))
need = {
    "secrets": {"rwsafe-snapshot-signing-key": ["rwsafe-snapshot-1.pem"], "rwsafe-privacy-hmac-key": ["key"],
                "rwsafe-db-credentials": ["spring.datasource.password", "rwsafe.migration.password"]},
    "configMaps": {"rwsafe-snapshot-public-keys": ["rwsafe-snapshot-1.pem"], "rwsafe-estate": ["estate-dictionary.txt"]},
}
missing = [f"{section}/{name}/{key}" for section, objects in need.items() for name, keys in objects.items()
           for key in keys if key not in (contract.get(section, {}).get(name, {}).get("keys") or [])]
if missing:
    print("not in the runtime contract: " + ", ".join(missing), file=sys.stderr)
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

exists() {   # exists <kind> <name>
  k -n "${NS}" get "$1" "$2" >/dev/null 2>&1
}

created=0
skipped=0
planned=0

create_secret() {   # create_secret <name> <dir holding one file per key>
  if [ "${PLAN}" = 1 ]; then echo "would create secret ${1}"; planned=$((planned + 1)); return; fi
  if ! labelled create "${NS}" secret generic "$1" --from-file="$2"; then
    echo "creating secret ${1} failed (kubectl output withheld; check access with: kubectl -n ${NS} auth can-i create secrets)" >&2
    return 1
  fi
  echo "created secret ${1}"
  created=$((created + 1))
}

create_configmap() {   # create_configmap <name> <dir holding one file per key>
  if [ "${PLAN}" = 1 ]; then echo "would create configmap ${1}"; planned=$((planned + 1)); return; fi
  if ! labelled create "${NS}" configmap "$1" --from-file="$2"; then
    echo "creating configmap ${1} failed (kubectl output withheld)" >&2
    return 1
  fi
  echo "created configmap ${1}"
  created=$((created + 1))
}

skip() {
  echo "exists, left as it is: $1"
  skipped=$((skipped + 1))
}

# 1. The snapshot signing key and its public key, as a pair.
SIGNING="${PRODUCT}-snapshot-signing-key"
PUBLIC="${PRODUCT}-snapshot-public-keys"
if exists secret "${SIGNING}" && exists configmap "${PUBLIC}"; then
  skip "secret ${SIGNING}"
  skip "configmap ${PUBLIC}"
elif exists secret "${SIGNING}" || exists configmap "${PUBLIC}"; then
  echo "only one of secret ${SIGNING} and configmap ${PUBLIC} exists; delete it and run again (both are made together)" >&2
  exit 1
else
  mkdir -p "${WORK}/signing" "${WORK}/public"
  if ! openssl genpkey -algorithm ed25519 -out "${WORK}/signing/rwsafe-snapshot-1.pem" 2>/dev/null \
      || ! openssl pkey -in "${WORK}/signing/rwsafe-snapshot-1.pem" -pubout \
           -out "${WORK}/public/rwsafe-snapshot-1.pem" 2>/dev/null; then
    echo "openssl could not make an Ed25519 key pair (OpenSSL 1.1.1 or later is needed; LibreSSL is not enough)" >&2
    exit 2
  fi
  create_secret "${SIGNING}" "${WORK}/signing" || exit 1
  if ! create_configmap "${PUBLIC}" "${WORK}/public"; then
    k -n "${NS}" delete secret "${SIGNING}" >/dev/null 2>&1 || true
    echo "the public key could not be stored; the signing key was removed again" >&2
    exit 1
  fi
fi

# 2. rwsafe's own privacy HMAC key: 32 random bytes (AGENTS.md 4.8; never neXus's).
HMAC="${PRODUCT}-privacy-hmac-key"
if exists secret "${HMAC}"; then
  skip "secret ${HMAC}"
else
  mkdir -p "${WORK}/hmac"
  head -c 32 /dev/urandom > "${WORK}/hmac/key"
  create_secret "${HMAC}" "${WORK}/hmac" || exit 1
fi

# 3. The two database role passwords (ADR-002): no trailing newline, the way the config tree and the image read them.
DB="${PRODUCT}-db-credentials"
if exists secret "${DB}"; then
  skip "secret ${DB}"
else
  mkdir -p "${WORK}/db"
  openssl rand -hex 24 2>/dev/null | tr -d '\n' > "${WORK}/db/spring.datasource.password"
  openssl rand -hex 24 2>/dev/null | tr -d '\n' > "${WORK}/db/rwsafe.migration.password"
  create_secret "${DB}" "${WORK}/db" || exit 1
fi

# 4. The estate dictionary with one synthetic placeholder term (a real term never comes from this repository).
ESTATE="${PRODUCT}-estate"
if exists configmap "${ESTATE}"; then
  skip "configmap ${ESTATE}"
else
  mkdir -p "${WORK}/estate"
  printf '%s\n' "# Pilot placeholder (tools/pilot/bootstrap_secrets.sh): replace with the estate's real terms," \
    "# one per line, before anyone uses the masked role (PILOT_RUNBOOK.md step 7)." \
    "pilot-placeholder-term-replace-me" > "${WORK}/estate/estate-dictionary.txt"
  create_configmap "${ESTATE}" "${WORK}/estate" || exit 1
fi

if [ "${PLAN}" = 1 ]; then
  echo "plan: ${planned} to create, ${skipped} existing; nothing changed"
else
  echo "done: ${created} created, ${skipped} existing; no value was printed"
fi
