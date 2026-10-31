#!/usr/bin/env bash
# Read-only pilot checks on the HOST-A terminal after the apply (PILOT_RUNBOOK.md step 13 and again after the proxy
# steps). Prints statuses and counts only: never an address, a host, pod or user name, a value of a Secret, or a prompt.
# The whole output also passes through tools/hosta/mask.sh (AGENTS.md 4.3), so an address that slipped into an error
# message reads <ip>. Changes nothing: `kubectl get`, short-lived `kubectl port-forward` to 127.0.0.1, one ICAP OPTIONS
# to the node's own address on 1344, and one counting query in the database pod.
#
#   pods          ready / total for the database, the control plane and the ICAP engine
#   control       GET /readyz on 8080 (200 only after Flyway ran and all four listeners are up)
#   icap pods     GET /ready on 9401 per pod (200 only with a verified policy snapshot loaded and not draining), and from
#                 /metrics: snapshot version, transactions, event queue depth, dropped events, spool bytes
#   servicelb     the LoadBalancer Service has a node address assigned and its ServiceLB pod is ready (the address itself
#                 is never printed)
#   icap options  ICAP OPTIONS for /reqmod-ai sent from this host to the node's address on 1344: status, Methods, Preview,
#                 Allow (what the ProxySG ICAP service must match)
#   events        verdict events stored in the last 24 hours by verdict class (counts), the proof that events arrive
#
# Usage: tools/pilot/check_pilot.sh
# Environment: PRODUCT (one-command override of product.env), KUBECTL (default `kubectl`), CHECK_PORT_BASE (first local
#              port for the port-forwards, default 19080)
# Exit: 0 every check passed, 1 at least one failed, 2 prerequisites missing
set -uo pipefail

# shellcheck source=tools/pilot/common.sh
. "$(dirname "$0")/common.sh"

PORT_BASE="${CHECK_PORT_BASE:-19080}"
FAILED=0

say() { printf '%-14s %s\n' "$1" "$2"; }
bad() { say "$1" "FAIL $2"; FAILED=1; }
good() { say "$1" "ok   $2"; }

forward() {   # forward <target> <remote port> <local port>; sets FWD_PID
  k -n "${NS}" port-forward "$1" "$3:$2" >/dev/null 2>&1 &
  FWD_PID=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$3/" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  return 0
}

unforward() {
  kill "${FWD_PID}" 2>/dev/null || true
  wait "${FWD_PID}" 2>/dev/null || true
}

http_code() {   # http_code <url>
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null || true
}

metric() {   # metric <metrics text> <name>: the value of an unlabelled series, or the sum of a labelled one
  printf '%s\n' "$1" | awk -v n="$2" '$1 == n || index($1, n "{") == 1 { s += $2; f = 1 } END { if (f) printf "%d", s; else printf "?" }'
}

check_pods() {
  local component name ready total
  for component in db control icap; do
    name="${PRODUCT}-${component}"
    ready="$(k -n "${NS}" get pods -l "app.kubernetes.io/name=${name}" \
      -o jsonpath='{range .items[*]}{.status.containerStatuses[0].ready}{"\n"}{end}' 2>/dev/null | grep -c '^true$' || true)"
    total="$(k -n "${NS}" get pods -l "app.kubernetes.io/name=${name}" -o name 2>/dev/null | grep -c . || true)"
    if [ "${total}" -gt 0 ] && [ "${ready}" = "${total}" ]; then
      good "pods" "${component}: ${ready}/${total} ready"
    else
      bad "pods" "${component}: ${ready}/${total} ready"
    fi
  done
}

check_control() {
  local port=$((PORT_BASE)) code
  forward "svc/${PRODUCT}-control" 8080 "${port}"
  code="$(http_code "http://127.0.0.1:${port}/readyz")"
  unforward
  if [ "${code}" = "200" ]; then good "control" "/readyz ${code}"; else bad "control" "/readyz ${code:-no answer}"; fi
}

check_icap_pods() {
  local pods n=0 pod port code text
  mapfile -t pods < <(k -n "${NS}" get pods -l "app.kubernetes.io/name=${PRODUCT}-icap" -o name 2>/dev/null)
  if [ "${#pods[@]}" -eq 0 ]; then bad "icap pods" "none found"; return; fi
  for pod in "${pods[@]}"; do
    n=$((n + 1))
    port=$((PORT_BASE + n))
    forward "${pod}" 9401 "${port}"
    code="$(http_code "http://127.0.0.1:${port}/ready")"
    text="$(curl -s --max-time 5 "http://127.0.0.1:${port}/metrics" 2>/dev/null || true)"
    unforward
    local detail
    detail="/ready ${code:-no answer}, snapshot version $(metric "${text}" icap_snapshot_version)"
    detail="${detail}, transactions $(metric "${text}" icap_transactions_total)"
    detail="${detail}, queue $(metric "${text}" icap_queue_depth), dropped $(metric "${text}" icap_queue_dropped_total)"
    detail="${detail}, spool bytes $(metric "${text}" icap_spool_bytes)"
    if [ "${code}" = "200" ] && [ "$(metric "${text}" icap_snapshot_version)" != "0" ]; then
      good "icap pod ${n}" "${detail}"
    else
      bad "icap pod ${n}" "${detail}"
    fi
  done
}

check_servicelb() {
  local assigned svclb_ready
  assigned="$(k -n "${NS}" get service "${PRODUCT}-icap-lb" \
    -o jsonpath='{.status.loadBalancer.ingress[*].ip}' 2>/dev/null | wc -w | tr -d ' ')"
  svclb_ready="$(k -n kube-system get pods -l "svccontroller.k3s.cattle.io/svcname=${PRODUCT}-icap-lb" \
    -o jsonpath='{range .items[*]}{.status.containerStatuses[0].ready}{"\n"}{end}' 2>/dev/null | grep -c '^true$' || true)"
  if [ "${assigned:-0}" -gt 0 ] && [ "${svclb_ready}" -gt 0 ]; then
    good "servicelb" "${assigned} node address(es) assigned, ${svclb_ready} ServiceLB pod(s) ready"
  else
    bad "servicelb" "${assigned:-0} node address(es) assigned, ${svclb_ready} ServiceLB pod(s) ready"
  fi
}

check_icap_options() {
  local address answer status methods preview allow
  address="$(k get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null)"
  if [ -z "${address}" ]; then bad "icap options" "the node address could not be read"; return; fi
  # The address goes only into the request; the answer's headers are filtered to the four below. The inner script is
  # single-quoted on purpose: it receives the address as its $1.
  # shellcheck disable=SC2016
  answer="$(timeout 10 bash -c '
    exec 3<>"/dev/tcp/$1/1344" || exit 1
    printf "OPTIONS icap://%s:1344/reqmod-ai ICAP/1.0\r\nHost: %s\r\nEncapsulated: null-body=0\r\n\r\n" "$1" "$1" >&3
    while IFS= read -r -t 5 line <&3; do
      line="$(printf "%s" "${line}" | tr -d "\r")"
      [ -z "${line}" ] && break
      printf "%s\n" "${line}"
    done
  ' _ "${address}" 2>/dev/null || true)"
  unset address
  status="$(printf '%s\n' "${answer}" | head -n 1 | awk '{print $2}')"
  methods="$(printf '%s\n' "${answer}" | sed -n 's/^Methods: *//p' | head -n 1)"
  preview="$(printf '%s\n' "${answer}" | sed -n 's/^Preview: *//p' | head -n 1)"
  allow="$(printf '%s\n' "${answer}" | sed -n 's/^Allow: *//p' | head -n 1)"
  if [ "${status}" = "200" ]; then
    good "icap options" "status 200, Methods ${methods:-?}, Preview ${preview:-?}, Allow ${allow:-?}"
  else
    bad "icap options" "status ${status:-no answer} (node address, port 1344)"
  fi
}

check_events() {
  local rows total
  # Counts by verdict class only; the database name is the application's internal one.
  rows="$(k -n "${NS}" exec "statefulset/${PRODUCT}-db" -c database -- psql -X -A -t -F ' ' -d rwsafe -c \
    "SELECT verdict, count(*) FROM verdict_event WHERE received_at > now() - interval '24 hours' GROUP BY verdict ORDER BY verdict" \
    2>/dev/null)" || { bad "events" "the counting query failed (UNVERIFIED local psql access, PILOT_RUNBOOK.md step 13)"; return; }
  total="$(printf '%s\n' "${rows}" | awk 'NF == 2 && $2 ~ /^[0-9]+$/ { s += $2 } END { printf "%d", s }')"
  if [ "${total}" -gt 0 ]; then
    good "events" "${total} in the last 24 hours: $(printf '%s\n' "${rows}" | awk 'NF == 2 && $2 ~ /^[0-9]+$/ { printf "%s %s; ", $1, $2 }')"
  else
    say "events" "none yet in the last 24 hours (expected before the first proxied request)"
  fi
}

main() {
  for tool in curl awk timeout; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "missing tool: ${tool}"; return 2; }
  done
  if ! k get namespace "${NS}" >/dev/null 2>&1; then
    echo "namespace ${NS} not found (or the cluster is not reachable with ${KUBECTL[*]})"
    return 2
  fi
  echo "pilot check, product ${PRODUCT}"
  check_pods
  check_control
  check_icap_pods
  check_servicelb
  check_icap_options
  check_events
  if [ "${FAILED}" = 0 ]; then echo "result: PASS"; return 0; fi
  echo "result: FAIL (see the lines marked FAIL)"
  return 1
}

main "$@" 2>&1 | sh "${PILOT_REPO}/tools/hosta/mask.sh"
exit "${PIPESTATUS[0]}"
