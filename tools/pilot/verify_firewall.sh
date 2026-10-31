#!/usr/bin/env bash
# The check right after the PO's host firewall step (PILOT_RUNBOOK.md step 11) and before the ServiceLB Service opens
# 1344 on the node (step 12). Prints statuses and counts only: never an address, a host, pod or user name, or a set
# element. The whole output also passes through tools/hosta/mask.sh (AGENTS.md 4.3).
#
# Two parts, because reading nftables needs root and the orchestrator never holds sudo (AGENTS.md section 8):
#
#   --table        the PO's one-line check (root): reads `nft -j list table inet <product>_pilot` on stdin and proves
#                  the table holds the set icap_clients with N elements (counted, never printed), the prerouting chain
#                  (filter hook, priority -150, policy accept) and the two drop rules for new TCP 1344 connections to the
#                  node's own addresses (IPv4 from outside @icap_clients; IPv6 from anywhere). A shape it does not
#                  recognise fails loudly (AGENTS.md section 7), it is never guessed.
#                    T="${PRODUCT//-/_}_pilot"; sudo nft -j list table inet "${T}" | tools/pilot/verify_firewall.sh --table
#
#   (default)      the orchestrator, as the host user without root:
#     icap pods    ready / total of the ICAP engine
#     through svc  one run of the synthetic probe (a Job created from the CronJob <product>-icap-probe, removed by its
#                  TTL a day later): ICAP OPTIONS and six REQMOD scenarios from a pod to the ClusterIP Service on 1344.
#                  PASS proves pod traffic to 1344 still flows through the prerouting hook the rule sits on (a rule that
#                  also matched pod or Service traffic, for example with Service addresses bound locally, drops it here).
#                  This creates one Job in the product's namespace: a host change, confirmed on its own (Q-45);
#                  `--latest` reads the newest finished probe Job instead and changes nothing.
#     node 1344    not served yet: no LoadBalancer Service in the namespace, no ServiceLB pod for <product>-icap-lb, no
#                  listening socket on 1344, and a TCP connection from this host to the node's own address on 1344 is
#                  refused (the host's own traffic is not filtered by the prerouting rule, so refused means nothing
#                  answers there; connected means 1344 is already served)
#
# Usage: tools/pilot/verify_firewall.sh [--latest]
#        sudo nft -j list table inet <product>_pilot | tools/pilot/verify_firewall.sh --table
# Environment: PRODUCT (one-command override of product.env), KUBECTL (default `kubectl`)
# Exit: 0 every check passed, 1 at least one failed, 2 prerequisites missing or usage
set -uo pipefail

# shellcheck source=tools/pilot/common.sh
. "$(dirname "$0")/common.sh"

FAILED=0
TABLE="${PRODUCT//-/_}_pilot"
PROBE="${PRODUCT}-icap-probe"

say() { printf '%-14s %s\n' "$1" "$2"; }
bad() { say "$1" "FAIL $2"; FAILED=1; }
good() { say "$1" "ok   $2"; }

# ---- the PO's part: the table, from `nft -j list table` on stdin ---------------------------------------------------------
check_table() {
  # The inner program prints one status line per check and exits 1 when any fails; it never prints a set element.
  python3 -I -c '
import json, sys

table = sys.argv[1]
try:
    doc = json.load(sys.stdin)
except ValueError:
    print("table          FAIL the input is not nft JSON (run: sudo nft -j list table inet %s | ...)" % table)
    print("result: FAIL (see the lines marked FAIL)")
    sys.exit(1)
items = doc.get("nftables") if isinstance(doc, dict) else None
if not isinstance(items, list):
    print("table          FAIL unrecognised nft JSON (no nftables list): protocol drift, stop and report")
    print("result: FAIL (see the lines marked FAIL)")
    sys.exit(1)
failed = False

def say(name, ok, text):
    global failed
    failed = failed or not ok
    print("%-14s %s %s" % (name, "ok  " if ok else "FAIL", text))

def objs(kind):
    return [i[kind] for i in items if isinstance(i, dict) and isinstance(i.get(kind), dict)
            and i[kind].get("table", table) == table and i[kind].get("family", "inet") == "inet"]

tables = [t for t in objs("table") if t.get("name") == table]
say("table", bool(tables), "inet %s %s" % (table, "present" if tables else "missing"))
others = [t for t in objs("table") if t.get("name") != table]
if others:
    say("table", False, "%d other table(s) in the input: list only the pilot table" % len(others))

sets = [s for s in objs("set") if s.get("name") == "icap_clients"]
elements = len((sets[0].get("elem") or [])) if sets else 0
say("set", bool(sets) and sets[0].get("type") == "ipv4_addr" and elements > 0,
    "icap_clients: %s, %d element(s) (values not shown; the pilot expects 3)" % (
        "type " + str(sets[0].get("type")) if sets else "missing", elements))

chains = [c for c in objs("chain") if c.get("name") == "prerouting"]
chain_ok = bool(chains) and chains[0].get("type") == "filter" and chains[0].get("hook") == "prerouting" \
    and chains[0].get("prio") == -150 and chains[0].get("policy") == "accept"
say("chain", chain_ok, "prerouting: %s" % (
    "type %s, hook %s, priority %s, policy %s" % tuple(chains[0].get(k) for k in ("type", "hook", "prio", "policy"))
    if chains else "missing"))

def matches(expr, left_key, test):
    for e in expr:
        m = e.get("match") if isinstance(e, dict) else None
        if isinstance(m, dict) and isinstance(m.get("left"), dict) and left_key(m["left"]) and test(m):
            return True
    return False

def local_daddr(left):
    f = left.get("fib")
    return isinstance(f, dict) and "daddr" in (f.get("flags") or []) and f.get("result") == "type"

def is_local(m):
    r = m.get("right")
    return m.get("op") in ("==", "in") and (r == "local" or r == ["local"] or (isinstance(r, dict) and "local" in json.dumps(r)))

def tcp_dport(left):
    p = left.get("payload")
    return isinstance(p, dict) and p.get("protocol") == "tcp" and p.get("field") == "dport"

def ct_state(left):
    c = left.get("ct")
    return isinstance(c, dict) and c.get("key") == "state"

def ip_saddr(left):
    p = left.get("payload")
    return isinstance(p, dict) and p.get("protocol") == "ip" and p.get("field") == "saddr"

def nfproto(left):
    m = left.get("meta")
    return isinstance(m, dict) and m.get("key") == "nfproto"

rules = [r for r in objs("rule") if r.get("chain") == "prerouting"]
v4 = v6 = 0
for r in rules:
    expr = r.get("expr") or []
    if not any(isinstance(e, dict) and "drop" in e for e in expr):
        continue
    if not (matches(expr, local_daddr, is_local) and matches(expr, tcp_dport, lambda m: m.get("right") == 1344)):
        continue
    if matches(expr, ip_saddr, lambda m: m.get("op") == "!=" and m.get("right") == "@icap_clients") \
            and matches(expr, ct_state, lambda m: "new" in json.dumps(m.get("right"))):
        v4 += 1
    elif matches(expr, nfproto, lambda m: m.get("right") == "ipv6"):
        v6 += 1
say("rules", v4 == 1 and v6 == 1 and len(rules) == 2,
    "%d rule(s) in prerouting; 1344 drop to local addresses: IPv4 outside @icap_clients %d, IPv6 %d (expected 1, 1)"
    % (len(rules), v4, v6))
print("result: %s" % ("FAIL (see the lines marked FAIL)" if failed else "PASS"))
sys.exit(1 if failed else 0)
' "${TABLE}"
}

# ---- the orchestrator's part --------------------------------------------------------------------------------------------
check_icap_pods() {
  local ready total
  ready="$(k -n "${NS}" get pods -l "app.kubernetes.io/name=${PRODUCT}-icap" \
    -o jsonpath='{range .items[*]}{.status.containerStatuses[0].ready}{"\n"}{end}' 2>/dev/null | grep -c '^true$' || true)"
  total="$(k -n "${NS}" get pods -l "app.kubernetes.io/name=${PRODUCT}-icap" -o name 2>/dev/null | grep -c . || true)"
  if [ "${total}" -gt 0 ] && [ "${ready}" = "${total}" ]; then
    good "icap pods" "${ready}/${total} ready"
  else
    bad "icap pods" "${ready}/${total} ready"
  fi
}

probe_report() {   # probe_report <job>: the probe's termination message (scenario names, outcomes, statuses only)
  k -n "${NS}" get pods -l "job-name=$1" \
    -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.message}' 2>/dev/null
}

judge_probe() {   # judge_probe <report> <where>
  local verdict mismatches
  verdict="$(printf '%s\n' "$1" | grep '^probe result:' | tail -n 1)"
  mismatches="$(printf '%s\n' "$1" | grep -c 'MISMATCH' || true)"
  case "${verdict}" in
    "probe result: PASS"*)
      good "through svc" "$2: ${verdict#probe result: }" ;;
    *)
      bad "through svc" "$2: ${verdict:-no probe report} (${mismatches} mismatch line(s))"
      printf '%s\n' "$1" | grep 'MISMATCH' | sed 's/^/               /' ;;
  esac
}

check_through_service_now() {
  local job
  job="${PROBE}-fw-$(date +%s)"
  if ! k get cronjob -n "${NS}" "${PROBE}" >/dev/null 2>&1; then
    bad "through svc" "CronJob ${PROBE} not found (apply step 9b first)"
    return
  fi
  if ! k -n "${NS}" create job "${job}" --from="cronjob/${PROBE}" >/dev/null 2>&1; then
    bad "through svc" "could not create the probe Job"
    return
  fi
  # Complete or failed, whichever comes first; the Job's own deadline is 120 s.
  local i state=""
  for i in $(seq 1 75); do
    state="$(k -n "${NS}" get job "${job}" \
      -o jsonpath='{range .status.conditions[?(@.status=="True")]}{.type}{"\n"}{end}' 2>/dev/null)"
    case "${state}" in *Complete*|*Failed*) break ;; esac
    sleep 2
  done
  judge_probe "$(probe_report "${job}")" "probe Job (now, $(printf '%s' "${state:-no condition}" | head -n 1))"
}

check_through_service_latest() {
  local job finished
  job="$(k -n "${NS}" get jobs -l "app.kubernetes.io/name=${PROBE}" \
    -o jsonpath='{range .items[?(@.status.completionTime)]}{.status.completionTime}{" "}{.metadata.name}{"\n"}{end}' \
    2>/dev/null | sort | tail -n 1)"
  if [ -z "${job}" ]; then
    # A failed Job has no completionTime; take the newest by start time then.
    job="$(k -n "${NS}" get jobs -l "app.kubernetes.io/name=${PROBE}" \
      -o jsonpath='{range .items[*]}{.status.startTime}{" "}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort | tail -n 1)"
  fi
  if [ -z "${job}" ]; then
    bad "through svc" "no probe Job yet (the CronJob runs every 15 minutes)"
    return
  fi
  finished="${job%% *}"
  judge_probe "$(probe_report "${job#* }")" "newest probe Job (started or finished ${finished})"
}

check_node_port_closed() {
  local lbs svclb listening address rc
  lbs="$(k -n "${NS}" get service -o jsonpath='{range .items[*]}{.spec.type}{"\n"}{end}' 2>/dev/null \
    | grep -c '^LoadBalancer$' || true)"
  svclb="$(k -n kube-system get pods -l "svccontroller.k3s.cattle.io/svcname=${PRODUCT}-icap-lb" -o name 2>/dev/null \
    | grep -c . || true)"
  listening="$(ss -ltnH 'sport = :1344' 2>/dev/null | grep -c . || true)"
  if [ "${lbs}" = 0 ] && [ "${svclb}" = 0 ] && [ "${listening}" = 0 ]; then
    good "node 1344" "no LoadBalancer Service, no ServiceLB pod, no listening socket"
  else
    bad "node 1344" "${lbs} LoadBalancer Service(s), ${svclb} ServiceLB pod(s), ${listening} listening socket(s)"
  fi
  address="$(k get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null)"
  if [ -z "${address}" ]; then bad "node 1344" "the node address could not be read"; return; fi
  # The address goes only into the connection; bash's own error text (which names it) is discarded. The inner script
  # is single-quoted on purpose: it receives the address as its $1.
  # shellcheck disable=SC2016
  timeout 5 bash -c 'exec 3<>"/dev/tcp/$1/1344"' _ "${address}" >/dev/null 2>&1
  rc=$?
  unset address
  case "${rc}" in
    0) bad "node 1344" "a connection from this host to the node address on 1344 succeeded: 1344 is already served" ;;
    124) bad "node 1344" "a connection from this host to the node address on 1344 timed out (expected refused): stop and report" ;;
    *) good "node 1344" "a connection from this host to the node address on 1344 is refused (nothing serves it yet)" ;;
  esac
}

main() {
  case "${1:-}" in
    --table)
      command -v python3 >/dev/null 2>&1 || { echo "missing tool: python3"; return 2; }
      echo "firewall table check, product ${PRODUCT}"
      check_table
      return $?
      ;;
    ""|--latest) ;;
    *) echo "usage: verify_firewall.sh [--latest] | verify_firewall.sh --table < nft-json"; return 2 ;;
  esac
  for tool in ss awk timeout seq; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "missing tool: ${tool}"; return 2; }
  done
  if ! k get namespace "${NS}" >/dev/null 2>&1; then
    echo "namespace ${NS} not found (or the cluster is not reachable with ${KUBECTL[*]})"
    return 2
  fi
  echo "firewall verification, product ${PRODUCT}"
  say "table" "not read here (root only): the PO's one-line check of step 11 (--table) proves it"
  check_icap_pods
  if [ "${1:-}" = "--latest" ]; then check_through_service_latest; else check_through_service_now; fi
  check_node_port_closed
  if [ "${FAILED}" = 0 ]; then echo "result: PASS"; return 0; fi
  echo "result: FAIL (see the lines marked FAIL)"
  return 1
}

main "$@" 2>&1 | sh "${PILOT_REPO}/tools/hosta/mask.sh"
exit "${PIPESTATUS[0]}"
