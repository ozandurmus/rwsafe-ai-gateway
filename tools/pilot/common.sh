# shellcheck shell=bash
# Shared prelude of the tools/pilot scripts (sourced, never run). Sets:
#   PILOT_REPO  the repository root
#   PRODUCT     the deployed product name: the PRODUCT= line of deploy/rwsafe/product.env (the one place it is set,
#               PO 2026-10-31), or the caller's PRODUCT environment value for one command; refused unless it passes
#               tools/deploy/manifest_check.validate_product (never a neXus or Kubernetes name)
#   NS          the runtime namespace (= PRODUCT); the build namespace is "${PRODUCT}-build"
#   KUBECTL     the kubectl command as an array, from the KUBECTL environment value (default `kubectl`; for example
#               KUBECTL="sudo k3s kubectl" when the kubeconfig is root-only)
# and the function k (runs "${KUBECTL[@]}"). Nothing here prints a value.

PILOT_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ -z "${PRODUCT:-}" ]; then
  PRODUCT="$(sed -n 's/^PRODUCT=//p' "${PILOT_REPO}/deploy/rwsafe/product.env" | tr -d "\"' ")"
fi
if ! python3 -B -c '
import sys
sys.path.insert(0, sys.argv[1])
import manifest_check
reason = manifest_check.validate_product(sys.argv[2])
if reason:
    print("product name refused: " + reason, file=sys.stderr)
    sys.exit(1)
' "${PILOT_REPO}/tools/deploy" "${PRODUCT}"; then
  exit 2
fi
NS="${PRODUCT}"
read -r -a KUBECTL <<< "${KUBECTL:-kubectl}"
export PILOT_REPO PRODUCT NS

k() {
  "${KUBECTL[@]}" "$@"
}
