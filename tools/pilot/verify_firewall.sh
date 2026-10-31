#!/usr/bin/env bash
# The check right after the PO's host firewall step (PILOT_RUNBOOK.md step 11) and before the ServiceLB Service opens
# 1344 on the node (step 12). Prints statuses and counts only: never an address, a host, pod or user name, or a set
# element. The whole output also passes through tools/hosta/mask.sh (AGENTS.md 4.3).
#
# Two parts, because reading nftables needs root and the orchestrator never holds sudo (AGENTS.md section 8):
#
#   --table        the PO's one-line check (root): reads `nft -j list table inet <product>_pilot` on stdin and passes
#                  only the exact table of step 11 (PR 40 review D-02): one table, one set icap_clients of type
#                  ipv4_addr with flags interval and exactly three single IPv4 addresses (counted, never printed; no
#                  prefix or range), one chain prerouting (filter hook, priority -150, policy accept) and exactly two
#                  rules whose every field and expression equals step 11's, operators included: every match is `==`
#                  (`ct state new` is nft's `in`), the one negation is the designed `ip saddr != @icap_clients`. Any
#                  other object, field, expression or rule fails, and so does a shape it does not recognise (AGENTS.md
#                  section 7): nothing is guessed.
#                    (set -euo pipefail; cd ~/rwsafe; P="$(sed -n 's/^PRODUCT=//p' deploy/rwsafe/product.env)";
#                     test -n "${P}"; sudo nft -j list table inet "${P//-/_}_pilot" | tools/pilot/verify_firewall.sh --table)
#
#   (default)      the orchestrator, as the host user without root:
#     icap pods    ready / total of the ICAP engine
#     through svc  one run of the synthetic probe (a Job created from the CronJob <product>-icap-probe, removed by its
#                  TTL a day later): ICAP OPTIONS and six REQMOD scenarios from a pod to the ClusterIP Service on 1344.
#                  PASS (the Job Complete and its report PASS) proves pod traffic to 1344 still flows through the
#                  prerouting hook the rule sits on (a rule that also matched pod or Service traffic, for example with
#                  Service addresses bound locally, drops it here). This creates one Job in the product's namespace: a
#                  host change, confirmed on its own (Q-45). `--latest` changes nothing: it judges the newest probe Job
#                  by creation time whatever its outcome (PR 40 review D-01): Failed or not finished is a FAIL.
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
import ipaddress, json, sys

table = sys.argv[1]
failed = False

def say(name, ok, text):
    global failed
    failed = failed or not ok
    print("%-14s %s %s" % (name, "ok  " if ok else "FAIL", text))

def finish():
    print("result: %s" % ("FAIL (see the lines marked FAIL)" if failed else "PASS"))
    sys.exit(1 if failed else 0)

try:
    doc = json.load(sys.stdin)
except ValueError:
    say("table", False, "the input is not nft JSON (run: sudo nft -j list table inet %s | ...)" % table)
    finish()
items = doc.get("nftables") if isinstance(doc, dict) else None
if not isinstance(items, list) or not all(isinstance(i, dict) and len(i) == 1 for i in items):
    say("table", False, "unrecognised nft JSON (no nftables list of single objects): protocol drift, stop and report")
    finish()

KINDS = ("metainfo", "table", "set", "chain", "rule")
other = [k for i in items for k in i if k not in KINDS]
say("objects", not other, "%d object(s) of another kind than table, set, chain, rule" % len(other))
of = {k: [i[k] for i in items if k in i and isinstance(i[k], dict)] for k in KINDS}

def fields(obj, expected):
    """True when the object carries exactly these fields (the handle aside) with these values."""
    return set(obj) - {"handle"} == set(expected) and all(obj.get(k) == v for k, v in expected.items())

tables = of["table"]
say("table", len(tables) == 1 and fields(tables[0], {"family": "inet", "name": table}),
    "inet %s: %d table(s) in the input, exactly 1 expected" % (table, len(tables)))

sets = of["set"]
elem = sets[0].get("elem") if len(sets) == 1 else None
def host_v4(e):
    try:
        return isinstance(e, str) and ipaddress.ip_address(e).version == 4
    except ValueError:
        return False
plain = isinstance(elem, list) and all(host_v4(e) for e in elem)
set_ok = len(sets) == 1 and set(sets[0]) - {"handle"} == {"family", "table", "name", "type", "flags", "elem"} \
    and fields({k: v for k, v in sets[0].items() if k != "elem"},
               {"family": "inet", "table": table, "name": "icap_clients", "type": "ipv4_addr", "flags": ["interval"]}) \
    and plain and len(elem) == 3
say("set", set_ok, "icap_clients: %d set(s), %d element(s), %s (values not shown; exactly 3 single IPv4 addresses "
    "expected)" % (len(sets), len(elem) if isinstance(elem, list) else 0,
                   "all single addresses" if plain else "not all single addresses"))

chains = of["chain"]
say("chain", len(chains) == 1 and fields(chains[0], {"family": "inet", "table": table, "name": "prerouting",
                                                     "type": "filter", "hook": "prerouting", "prio": -150,
                                                     "policy": "accept"}),
    "%d chain(s); exactly 1 expected: prerouting, type filter, hook prerouting, priority -150, policy accept"
    % len(chains))

def match(op, left, right):
    return {"match": {"op": op, "left": left, "right": right}}

LOCAL = match("==", {"fib": {"result": "type", "flags": ["daddr"]}}, "local")
DPORT = match("==", {"payload": {"protocol": "tcp", "field": "dport"}}, 1344)
CT_NEW = match("in", {"ct": {"key": "state"}}, "new")
NOT_CLIENTS = match("!=", {"payload": {"protocol": "ip", "field": "saddr"}}, "@icap_clients")
IPV6 = match("==", {"meta": {"key": "nfproto"}}, "ipv6")
DROP = {"drop": None}
EXPECTED = {"IPv4": [LOCAL, DPORT, CT_NEW, NOT_CLIENTS, DROP], "IPv6": [LOCAL, IPV6, DPORT, DROP]}

def canonical(expr):
    """`ct state new` is printed with op `in` (a bitmask) or `==` by nft releases; both mean the same, nothing else is
    rewritten."""
    out = []
    for e in expr if isinstance(expr, list) else []:
        m = e.get("match") if isinstance(e, dict) else None
        if isinstance(m, dict) and m.get("left") == {"ct": {"key": "state"}} and m.get("op") in ("==", "in") \
                and m.get("right") in ("new", ["new"]):
            e = CT_NEW
        out.append(e)
    return out

rules = of["rule"]
found = []
for r in rules:
    kind = next((k for k, v in EXPECTED.items() if canonical(r.get("expr")) == v), None)
    ok = kind is not None and fields(r, {"family": "inet", "table": table, "chain": "prerouting", "expr": r.get("expr")})
    found.append(kind if ok else None)
say("rules", sorted(k or "" for k in found) == ["IPv4", "IPv6"],
    "%d rule(s); exactly 2 expected, each equal to step 11 in every field and operator: IPv4 %d, IPv6 %d, other %d"
    % (len(rules), found.count("IPv4"), found.count("IPv6"), found.count(None)))
finish()
' "${TABLE}"
}

# ---- the orchestrator's part --------------------------------------------------------------------------------------------
check_icap_pods() {
  local ready total
  ready="$(k -n "${NS}" get pods -l "app.kubernetes.io/name=${PRODUCT}-icap,app.kubernetes.io/component=icap" \
    --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.status.containerStatuses[0].ready}{"\n"}{end}' 2>/dev/null | grep -c '^true$' || true)"
  total="$(k -n "${NS}" get pods -l "app.kubernetes.io/name=${PRODUCT}-icap,app.kubernetes.io/component=icap" --field-selector=status.phase!=Succeeded -o name 2>/dev/null | grep -c . || true)"
  if [ "${total}" -gt 0 ] && [ "${ready}" = "${total}" ]; then
    good "icap pods" "${ready}/${total} ready"
  else
    bad "icap pods" "${ready}/${total} ready"
  fi
}

job_state() {   # job_state <job>: Complete, Failed or running (the Job's terminal condition)
  local conditions
  conditions="$(k -n "${NS}" get job "$1" \
    -o jsonpath='{range .status.conditions[?(@.status=="True")]}{.type}{"\n"}{end}' 2>/dev/null)"
  case "${conditions}" in
    *Failed*) echo "Failed" ;;
    *Complete*) echo "Complete" ;;
    *) echo "running" ;;
  esac
}

probe_report() {   # probe_report <job>: the probe's termination message (scenario names, outcomes, statuses only)
  k -n "${NS}" get pods -l "job-name=$1" \
    -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.message}' 2>/dev/null
}

judge_job() {   # judge_job <job> <where>: PASS only for a Complete Job whose report says PASS
  local state report verdict mismatches
  state="$(job_state "$1")"
  report="$(probe_report "$1")"
  verdict="$(printf '%s\n' "${report}" | grep '^probe result:' | tail -n 1)"
  mismatches="$(printf '%s\n' "${report}" | grep -c 'MISMATCH' || true)"
  case "${state}:${verdict}" in
    "Complete:probe result: PASS"*)
      good "through svc" "$2, Job ${state}: ${verdict#probe result: }" ;;
    *)
      bad "through svc" "$2, Job ${state}: ${verdict:-no probe report} (${mismatches} mismatch line(s))"
      printf '%s\n' "${report}" | grep -E 'MISMATCH|^probe result: FAIL \(' | sed 's/^/               /' ;;
  esac
}

check_through_service_now() {
  local job i
  job="${PROBE}-fw-$(date +%s)"
  if ! k get cronjob -n "${NS}" "${PROBE}" >/dev/null 2>&1; then
    bad "through svc" "CronJob ${PROBE} not found (apply step 9b first)"
    return
  fi
  if ! k -n "${NS}" create job "${job}" --from="cronjob/${PROBE}" >/dev/null 2>&1; then
    bad "through svc" "could not create the probe Job"
    return
  fi
  # Complete or Failed, whichever comes first; the Job's own deadline is 120 s.
  for i in $(seq 1 75); do
    [ "$(job_state "${job}")" = running ] || break
    sleep 2
  done
  judge_job "${job}" "probe Job (now)"
}

check_through_service_latest() {
  local newest
  # PR 40 review D-01: the newest probe Job by creation time, whatever its outcome (a Failed Job has no completionTime,
  # so selecting by completion would skip it and report an older PASS).
  newest="$(k -n "${NS}" get jobs -l "app.kubernetes.io/name=${PROBE}" \
    -o jsonpath='{range .items[*]}{.metadata.creationTimestamp}{" "}{.metadata.name}{"\n"}{end}' 2>/dev/null \
    | sort | tail -n 1)"
  if [ -z "${newest}" ]; then
    bad "through svc" "no probe Job yet (the CronJob runs every 15 minutes)"
    return
  fi
  judge_job "${newest#* }" "newest probe Job (created ${newest%% *})"
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
