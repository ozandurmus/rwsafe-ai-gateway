# shellcheck shell=bash
# Shared prelude of the tools/pilot scripts (sourced, never run). Sets:
#   PILOT_REPO  the repository root
#   PRODUCT     the deployed product name: the PRODUCT= line of deploy/rwsafe/product.env (the one place it is set,
#               PO 2026-10-31), or the caller's PRODUCT environment value for one command; refused unless it passes
#               tools/deploy/manifest_check.validate_product (never a neXus or Kubernetes name)
#   NS          the runtime namespace (= PRODUCT); the build namespace is "${PRODUCT}-build"
#   KUBECTL     the kubectl command as an array, from the KUBECTL environment value (default `kubectl`): the host
#               user's own kubectl and kubeconfig. Never `sudo` (AGENTS.md section 8, decision Q-45 point 3): a KUBECTL
#               that runs sudo is refused.
# and the functions k (runs "${KUBECTL[@]}") and labelled (creates or applies one object labelled part-of the product,
# with every kubectl output discarded). Nothing here prints a value.

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
for word in "${KUBECTL[@]}"; do
  case "${word##*/}" in
    sudo|doas|su|pkexec)
      echo "KUBECTL must be the host user's own kubectl, never through ${word##*/} (AGENTS.md section 8, Q-45)" >&2
      exit 2 ;;
  esac
done
export PILOT_REPO PRODUCT NS

k() {
  "${KUBECTL[@]}" "$@"
}

# labelled <create|apply> <namespace> <arguments of `kubectl create`>
# Builds the object client-side (`--dry-run=client -o json`), labels it part-of the product, then creates (or applies)
# it in one call, so an object never exists unlabelled (PR 33 review D-07). Values travel only through the pipes between
# the kubectl processes; stdout and stderr of every kubectl are discarded, so no value reaches a terminal or a log (PR 33
# review D-03). Returns non-zero when any part fails (the caller sets pipefail).
labelled() {
  local mode="$1" namespace="$2"
  shift 2
  k -n "${namespace}" create "$@" --dry-run=client -o json 2>/dev/null \
    | k label --local -f - "app.kubernetes.io/part-of=${PRODUCT}" -o json 2>/dev/null \
    | k -n "${namespace}" "${mode}" -f - >/dev/null 2>&1
}
