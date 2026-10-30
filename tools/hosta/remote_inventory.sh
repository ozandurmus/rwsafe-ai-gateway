#!/usr/bin/env bash
# Runs ON HOST-A, fed through `ssh <host> bash -s`. Read-only: kubectl get/raw, ss, df, lsblk, sysctl, /proc. No sudo, no exec,
# no logs, no writes. Node and host names are replaced by <node> here, before they leave the host; addresses are masked
# again by the caller. Values that cannot be read without root print as UNREADABLE and are collected by the PO's sudo pass.
set -u
export KUBECONFIG=$HOME/.kube/config
section() { printf '\n===== %s =====\n' "$1"; }
NODE=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
HOSTN=$(hostname 2>/dev/null); HOSTS=$(hostname -s 2>/dev/null)
nodemask() {
  local expr=""
  for n in "$NODE" "$HOSTN" "$HOSTS"; do [ -n "$n" ] && [ "${#n}" -ge 3 ] && expr="$expr -e s/${n//\//\\/}/<node>/g"; done
  if [ -n "$expr" ]; then sed $expr; else cat; fi
}
run() { "$@" 2>&1 | nodemask; }
py() { python3 -c "$1" 2>&1 | nodemask; }

section "meta"
echo "collected_at_utc=$(date -u +%FT%TZ)"
echo "node_count=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')"
echo "kubectl_user_can_list_nodes=$(kubectl auth can-i list nodes 2>/dev/null)"
echo "kubectl_user_can_get_secrets_kube_system=$(kubectl auth can-i get secrets -n kube-system 2>/dev/null)"

section "os"
run grep -E '^(NAME|VERSION|VERSION_ID)=' /etc/os-release
run uname -r
run uptime -p
echo "timezone=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UNKNOWN)"
echo "ntp_synchronized=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo UNKNOWN)"

section "cpu_memory"
echo "nproc=$(nproc)"
run lscpu | grep -E '^(Model name|CPU\(s\)|Thread\(s\) per core|Core\(s\) per socket|Socket\(s\)|Hypervisor vendor|Virtualization type)'
run free -m
run grep -E '^(MemTotal|SwapTotal|HugePages_Total)' /proc/meminfo

section "disk"
run df -BG -x tmpfs -x devtmpfs -x overlay -x squashfs --output=source,fstype,size,used,avail,pcent,target
run lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
for p in /var/lib/rancher /var/lib/rancher/k3s/storage /var/lib/kubelet /var/backups /var/lib/rancher/k3s/agent /var/log; do
  if [ -d "$p" ]; then printf '%s -> ' "$p"; df -BG --output=target,size,used,avail,pcent "$p" 2>/dev/null | tail -1; else echo "$p -> ABSENT"; fi
done
echo "--- du (non-root; UNREADABLE expected for root-owned paths)"
for p in /var/lib/rancher/k3s/storage /var/backups/nexus /var/lib/registry; do
  if [ -d "$p" ]; then du -sh "$p" 2>/dev/null || echo "$p du=UNREADABLE"; else echo "$p ABSENT"; fi
done

section "kernel_limits"
run sysctl -n net.core.somaxconn net.ipv4.ip_local_port_range fs.file-max net.ipv4.tcp_max_syn_backlog vm.overcommit_memory vm.max_map_count fs.inotify.max_user_instances
echo "ulimit_n=$(ulimit -n)"
echo "proxy_env_vars=$(env | grep -ci proxy)"
echo "etc_environment_proxy_lines=$(grep -ci proxy /etc/environment 2>/dev/null || echo UNREADABLE)"
echo "k3s_service_env_readable=$([ -r /etc/systemd/system/k3s.service.env ] && echo yes || echo no)"
echo "k3s_config_readable=$([ -r /etc/rancher/k3s/config.yaml ] && echo yes || echo no)"
echo "k3s_manifests_dir_listable=$(ls /var/lib/rancher/k3s/server/manifests/ >/dev/null 2>&1 && echo yes || echo no)"
echo "etc_nexus_listable=$(ls /etc/nexus/ >/dev/null 2>&1 && echo yes || echo no)"

section "k3s_config_keys (values of identity, token and address keys withheld)"
if [ -r /etc/rancher/k3s/config.yaml ]; then
  sed -E -e 's/^(\s*-?\s*)(token|agent-token|tls-san|node-ip|node-external-ip|advertise-address|bind-address|datastore-endpoint|cluster-cidr|service-cidr|cluster-dns|node-name|server|flannel-iface)(:?\s).*/\1\2\3<withheld>/' /etc/rancher/k3s/config.yaml | nodemask
else echo UNREADABLE; fi
echo "--- /etc/nexus listing (names only)"
run ls -la /etc/nexus/
echo "--- kube-system pods"
run kubectl -n kube-system get pods -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,PRIO:.spec.priorityClassName,HOSTNET:.spec.hostNetwork

section "k3s_versions_and_node"
run sh -c 'k3s --version 2>/dev/null || echo "k3s binary not on PATH for this user"'
kubectl get nodes -o json 2>/dev/null | py "$(cat <<'PY'
import json,sys
d=json.load(sys.stdin)
for n in d.get("items",[]):
    st=n["status"]; ni=st.get("nodeInfo",{})
    print("kubelet_version=",ni.get("kubeletVersion")); print("runtime=",ni.get("containerRuntimeVersion"))
    print("os_image=",ni.get("osImage")); print("kernel=",ni.get("kernelVersion")); print("arch=",ni.get("architecture"))
    print("capacity=",json.dumps(st.get("capacity"))); print("allocatable=",json.dumps(st.get("allocatable")))
    print("conditions=",", ".join(f'{c["type"]}={c["status"]}' for c in st.get("conditions",[])))
    print("taints=",json.dumps(n["spec"].get("taints",[])))
    print("labels_keys=",sorted(k for k in n["metadata"].get("labels",{}) if "kubernetes.io/hostname" not in k))
    print("addresses_count_by_type=",{a["type"]:1 for a in st.get("addresses",[])})
PY
)"

section "kubelet_config_via_api"
if [ -n "$NODE" ]; then
kubectl get --raw "/api/v1/nodes/$NODE/proxy/configz" 2>/dev/null | py "$(cat <<'PY'
import json,sys
try:
    k=json.load(sys.stdin).get("kubeletconfig",{})
except Exception as e:
    print("UNAVAILABLE",type(e).__name__); sys.exit(0)
for key in ("evictionHard","evictionSoft","evictionSoftGracePeriod","evictionMinimumReclaim","imageGCHighThresholdPercent","imageGCLowThresholdPercent","imageMinimumGCAge","maxPods","podPidsLimit","protectKernelDefaults","systemReserved","kubeReserved","enforceNodeAllocatable","containerLogMaxSize","containerLogMaxFiles","serializeImagePulls","maxParallelImagePulls","cpuManagerPolicy","memoryManagerPolicy","registerWithTaints","shutdownGracePeriod","nodeStatusUpdateFrequency"):
    if key in k: print(f"{key}={json.dumps(k[key])}")
PY
)"
fi

section "kubelet_stats_summary_via_api"
if [ -n "$NODE" ]; then
kubectl get --raw "/api/v1/nodes/$NODE/proxy/stats/summary" 2>/dev/null | py "$(cat <<'PY'
import json,sys
try:
    s=json.load(sys.stdin)
except Exception as e:
    print("UNAVAILABLE",type(e).__name__); sys.exit(0)
n=s.get("node",{})
def gb(x): return "UNKNOWN" if x is None else f"{x/2**30:.1f}Gi"
fs=n.get("fs",{}); print("node_fs capacity=",gb(fs.get("capacityBytes")),"used=",gb(fs.get("usedBytes")),"available=",gb(fs.get("availableBytes")),"inodesFree=",fs.get("inodesFree"))
ifs=n.get("runtime",{}).get("imageFs",{}); print("image_fs capacity=",gb(ifs.get("capacityBytes")),"used=",gb(ifs.get("usedBytes")),"available=",gb(ifs.get("availableBytes")))
m=n.get("memory",{}); print("node_memory workingSet=",gb(m.get("workingSetBytes")),"available=",gb(m.get("availableBytes")),"rss=",gb(m.get("rssBytes")))
c=n.get("cpu",{}); print("node_cpu usageNanoCores=",c.get("usageNanoCores"))
print("--- per-namespace memory workingSet and cpu")
agg={}
for p in s.get("pods",[]):
    ns=p["podRef"]["namespace"]; a=agg.setdefault(ns,[0,0,0])
    a[0]+=p.get("memory",{}).get("workingSetBytes",0) or 0; a[1]+=p.get("cpu",{}).get("usageNanoCores",0) or 0; a[2]+=1
for ns,(mem,cpu,cnt) in sorted(agg.items()): print(f"{ns}: pods={cnt} workingSet={gb(mem)} cpu_mcores={cpu/1e6:.0f}")
print("--- persistent volume usage by claim")
for p in s.get("pods",[]):
    for v in p.get("volume",[]):
        ref=v.get("pvcRef")
        if ref: print(f'{ref["namespace"]}/{ref["name"]}: used={gb(v.get("usedBytes"))} capacity={gb(v.get("capacityBytes"))} available={gb(v.get("availableBytes"))}')
print("--- ephemeral (writable layer + emptyDir + logs) per pod > 200Mi")
for p in s.get("pods",[]):
    e=p.get("ephemeral-storage",{}).get("usedBytes",0) or 0
    if e>200*2**20: print(f'{p["podRef"]["namespace"]}/{p["podRef"]["name"]}: {gb(e)}')
PY
)"
fi

section "listening_ports_tcp (proto port bind_scope process; non-root sees own processes only)"
ss -ltnH 2>/dev/null | awk '{addr=$4; n=split(addr,a,":"); port=a[n]; local=substr(addr,1,length(addr)-length(port)-1); scope=(local=="*"||local=="0.0.0.0"||local=="[::]"||local=="::")?"ANY":(local=="127.0.0.1"||local=="[::1]")?"LOOPBACK":"SPECIFIC"; print "tcp", port, scope}' | sort -k2 -n | uniq -c
echo "--- process names visible to this user"
ss -ltnpH 2>/dev/null | sed -nE 's/.*:([0-9]+) +[^ ]+ +users:\(\("([^"]+)".*/\1 \2/p' | sort -n | uniq
section "listening_ports_udp"
ss -lunH 2>/dev/null | awk '{addr=$4; n=split(addr,a,":"); port=a[n]; local=substr(addr,1,length(addr)-length(port)-1); scope=(local=="*"||local=="0.0.0.0"||local=="[::]"||local=="::")?"ANY":(local=="127.0.0.1"||local=="[::1]")?"LOOPBACK":"SPECIFIC"; print "udp", port, scope}' | sort -k2 -n | uniq -c

section "namespaces"
kubectl get ns -o json 2>/dev/null | py "$(cat <<'PY'
import json,sys
for n in json.load(sys.stdin).get("items",[]):
    labels={k:v for k,v in n["metadata"].get("labels",{}).items() if k.startswith("pod-security") or k.startswith("app.kubernetes.io")}
    print(n["metadata"]["name"], n["status"]["phase"], json.dumps(labels))
PY
)"

section "services (ns name type port->target nodePort proto; cluster addresses omitted)"
kubectl get svc -A -o json 2>/dev/null | py "$(cat <<'PY'
import json,sys
for s in json.load(sys.stdin).get("items",[]):
    sp=s["spec"]; ports=["%s:%s->%s%s"%(p.get("protocol","TCP"),p.get("port"),p.get("targetPort"),(" nodePort=%s"%p["nodePort"]) if p.get("nodePort") else "") for p in sp.get("ports",[])]
    extra=[]
    if sp.get("externalIPs"): extra.append("externalIPs=%d"%len(sp["externalIPs"]))
    if sp.get("externalTrafficPolicy"): extra.append("etp="+sp["externalTrafficPolicy"])
    if s.get("status",{}).get("loadBalancer",{}).get("ingress"): extra.append("lbIngress=%d"%len(s["status"]["loadBalancer"]["ingress"]))
    print(s["metadata"]["namespace"], s["metadata"]["name"], sp.get("type"), " ".join(ports), " ".join(extra))
PY
)"

section "workloads (ns kind name replicas strategy priorityClass digestPinned hostPort hostNetwork hostPath diskPressureToleration)"
kubectl get deploy,sts,ds -A -o json 2>/dev/null | py "$(cat <<'PY'
import json,sys
for w in json.load(sys.stdin).get("items",[]):
    sp=w["spec"]; tpl=sp["template"]["spec"]; st=w.get("status",{})
    strat=sp.get("strategy",sp.get("updateStrategy",{})).get("type")
    ru=sp.get("strategy",sp.get("updateStrategy",{})).get("rollingUpdate")
    conts=tpl.get("containers",[])+tpl.get("initContainers",[])
    pinned=all("@sha256:" in c["image"] for c in conts) if conts else None
    hostport=any(p.get("hostPort") for c in conts for p in c.get("ports",[]))
    hostpath=sum(1 for v in tpl.get("volumes",[]) if "hostPath" in v)
    dp=any(t.get("key")=="node.kubernetes.io/disk-pressure" for t in tpl.get("tolerations",[]))
    print(w["metadata"]["namespace"], w["kind"], w["metadata"]["name"], "replicas=%s/%s"%(st.get("readyReplicas",st.get("numberReady",0)),sp.get("replicas",st.get("desiredNumberScheduled"))),
          "strategy=%s%s"%(strat, " "+json.dumps(ru) if ru else ""), "prio=%s"%tpl.get("priorityClassName"), "pinned=%s"%pinned, "hostPort=%s"%hostport,
          "hostNetwork=%s"%tpl.get("hostNetwork",False), "hostPath=%d"%hostpath, "diskPressureTol=%s"%dp)
PY
)"

section "pods_resources (per namespace sums for running pods; requests/limits in millicores and Mi)"
kubectl get pods -A -o json 2>/dev/null | py "$(cat <<'PY'
import json,sys,re
def cpu(v):
    if v is None: return 0
    v=str(v); return int(v[:-1]) if v.endswith("m") else int(float(v)*1000)
def mem(v):
    if v is None: return 0
    v=str(v); m=re.match(r"^([0-9.]+)([A-Za-z]*)$",v)
    if not m: return 0
    n=float(m.group(1)); u=m.group(2)
    f={"Ki":1/1024,"Mi":1,"Gi":1024,"Ti":1024**2,"K":1e3/2**20,"M":1e6/2**20,"G":1e9/2**20,"":1/2**20}
    return n*f.get(u,1)
d=json.load(sys.stdin)
agg={}; phases={}; nolimit=[]; prio={}
for p in d.get("items",[]):
    ns=p["metadata"]["namespace"]; ph=p["status"].get("phase")
    phases.setdefault(ns,{}); phases[ns][ph]=phases[ns].get(ph,0)+1
    prio.setdefault(ns,set()).add(p["spec"].get("priorityClassName"))
    if ph not in ("Running","Pending"): continue
    a=agg.setdefault(ns,[0,0,0,0])
    for c in p["spec"].get("containers",[]):
        r=c.get("resources",{}); rq=r.get("requests",{}); li=r.get("limits",{})
        a[0]+=cpu(rq.get("cpu")); a[1]+=mem(rq.get("memory")); a[2]+=cpu(li.get("cpu")); a[3]+=mem(li.get("memory"))
        if not li.get("cpu") or not li.get("memory"): nolimit.append(f'{ns}/{p["metadata"]["name"]}:{c["name"]} cpu_limit={li.get("cpu")} mem_limit={li.get("memory")}')
tot=[0,0,0,0]
for ns,(rc,rm,lc,lm) in sorted(agg.items()):
    print(f"{ns}: req_cpu={rc}m req_mem={rm:.0f}Mi lim_cpu={lc}m lim_mem={lm:.0f}Mi phases={phases.get(ns)} prioClasses={sorted(str(x) for x in prio.get(ns,[]))}")
    for i,v in enumerate((rc,rm,lc,lm)): tot[i]+=v
print(f"TOTAL: req_cpu={tot[0]}m req_mem={tot[1]:.0f}Mi lim_cpu={tot[2]}m lim_mem={tot[3]:.0f}Mi")
print("--- containers without a cpu or memory limit (running/pending)")
for x in nolimit: print(x)
PY
)"

section "ingress (ns name class tls_count rules: host? path -> service:port)"
kubectl get ingress -A -o json 2>/dev/null | py "$(cat <<'PY'
import json,sys
for i in json.load(sys.stdin).get("items",[]):
    sp=i["spec"]; print(i["metadata"]["namespace"], i["metadata"]["name"], "class=%s"%sp.get("ingressClassName"), "tls=%d"%len(sp.get("tls",[])), "annotations=%s"%sorted(i["metadata"].get("annotations",{}).keys()))
    for r in sp.get("rules",[]):
        host="<host>" if r.get("host") else "(none: catch-all)"
        for p in r.get("http",{}).get("paths",[]):
            b=p.get("backend",{}).get("service",{}); print("   ",host,p.get("pathType"),p.get("path"),"->",b.get("name"),(b.get("port") or {}))
    if sp.get("defaultBackend"): print("    defaultBackend=",json.dumps(sp["defaultBackend"]))
PY
)"
echo "--- traefik CRDs"
run kubectl get ingressroute,ingressroutetcp,ingressrouteudp,middleware,tlsoption,tlsstore,serverstransport -A
echo "--- traefik service"
kubectl -n kube-system get svc traefik -o json 2>/dev/null | py "$(cat <<'PY'
import json,sys
s=json.load(sys.stdin); sp=s["spec"]
print("type=",sp.get("type"),"etp=",sp.get("externalTrafficPolicy"),"ports=",[(p.get("name"),p.get("port"),p.get("targetPort"),p.get("nodePort")) for p in sp.get("ports",[])])
PY
)"
echo "--- traefik deployment args and ports"
kubectl -n kube-system get deploy traefik -o json 2>/dev/null | py "$(cat <<'PY'
import json,sys
d=json.load(sys.stdin); c=d["spec"]["template"]["spec"]["containers"][0]
print("image_repo=",c["image"].split("@")[0].split(":")[0]); print("args=",json.dumps(c.get("args",[])))
print("ports=",[(p.get("name"),p.get("containerPort"),p.get("hostPort")) for p in c.get("ports",[])])
print("hostNetwork=",d["spec"]["template"]["spec"].get("hostNetwork",False))
PY
)"
echo "--- traefik helm chart config (values)"
run kubectl -n kube-system get helmchartconfig traefik -o jsonpath='{.spec.valuesContent}'
echo
echo "--- tls secrets in kube-system (names)"
run kubectl -n kube-system get secrets --field-selector type=kubernetes.io/tls -o custom-columns=NAME:.metadata.name
echo "--- default TLS certificate (shape only)"
kubectl -n kube-system get secret nexus-default-tls -o jsonpath='{.data.tls\.crt}' 2>/dev/null | base64 -d 2>/dev/null | py "$(cat <<'PY'
import subprocess,sys,re
pem=sys.stdin.read()
if not pem.strip(): print("secret nexus-default-tls: ABSENT or UNREADABLE"); sys.exit(0)
out=subprocess.run(["openssl","x509","-noout","-subject","-issuer","-dates","-ext","subjectAltName,basicConstraints"],input=pem,capture_output=True,text=True).stdout
subj=re.search(r"subject=(.*)",out); iss=re.search(r"issuer=(.*)",out)
print("self_signed_or_same_issuer=", bool(subj and iss and subj.group(1).strip()==iss.group(1).strip()))
for k in ("notBefore","notAfter"):
    m=re.search(k+r"=(.*)",out); print(k+"=",m.group(1) if m else "UNKNOWN")
sans=re.findall(r"DNS:([^,\s]+)",out); ips=re.findall(r"IP Address:([^,\s]+)",out)
print("san_dns_count=",len(sans),"san_dns_wildcards=",sum(1 for s in sans if s.startswith("*.")),"san_ip_count=",len(ips))
print("san_dns_label_depths=",sorted(set(s.count(".")+1 for s in sans)))
PY
)"

section "quotas_limits_netpol_priority_pdb"
run kubectl get resourcequota -A
run kubectl get limitrange -A
run kubectl get networkpolicy -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,TYPES:.spec.policyTypes
run kubectl get priorityclass -o custom-columns=NAME:.metadata.name,VALUE:.value,GLOBALDEFAULT:.globalDefault,PREEMPTION:.preemptionPolicy
run kubectl get pdb -A

section "storage"
run kubectl get storageclass
run kubectl get pvc -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,STATUS:.status.phase,CAPACITY:.status.capacity.storage,ACCESS:.spec.accessModes,CLASS:.spec.storageClassName
run kubectl get pv -o custom-columns=NAME:.metadata.name,CAPACITY:.spec.capacity.storage,RECLAIM:.spec.persistentVolumeReclaimPolicy,STATUS:.status.phase,CLAIM:.spec.claimRef.namespace,CLAIMNAME:.spec.claimRef.name,CLASS:.spec.storageClassName

section "cronjobs_jobs"
run kubectl get cronjob -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,SCHEDULE:.spec.schedule,TZ:.spec.timeZone,SUSPEND:.spec.suspend,CONCURRENCY:.spec.concurrencyPolicy
echo "jobs_total=$(kubectl get job -A --no-headers 2>/dev/null | wc -l | tr -d ' ')"

section "warning_events_by_reason (last window, counts only)"
kubectl get events -A --field-selector type=Warning -o json 2>/dev/null | py "$(cat <<'PY'
import json,sys
c={}
for e in json.load(sys.stdin).get("items",[]):
    k=(e["metadata"]["namespace"], e.get("reason"), e.get("involvedObject",{}).get("kind")); c[k]=c.get(k,0)+e.get("count",1)
for k,v in sorted(c.items(), key=lambda kv:-kv[1])[:25]: print(v, *k)
PY
)"

section "registry (image names and tag counts; addresses withheld)"
REG=$(kubectl -n kube-system get svc registry -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
if [ -n "$REG" ]; then
  echo "registry_image=$(kubectl -n kube-system get deploy registry -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null | sed 's/@.*//')"
  REG="$REG" py "$(cat <<'PY'
import json,os,urllib.request
base="http://%s/v2/"%os.environ["REG"]
def get(u):
    with urllib.request.urlopen(u,timeout=5) as r: return json.load(r)
try:
    cat=get(base+"_catalog?n=200")
except Exception as e:
    print("catalog UNAVAILABLE",type(e).__name__); raise SystemExit
for repo in cat.get("repositories",[]):
    try: tags=get(base+repo+"/tags/list").get("tags") or []
    except Exception as e: tags=["ERR:"+type(e).__name__]
    print(repo, "tags=%d"%len(tags))
PY
)"
else echo "registry service: ABSENT"; fi

section "secrets_and_configmaps_count_by_namespace (names only, no values read)"
run kubectl get secrets -A --no-headers -o custom-columns=NS:.metadata.namespace,TYPE:.type | sort | uniq -c
run kubectl get configmap -A --no-headers -o custom-columns=NS:.metadata.namespace | sort | uniq -c

section "end"
echo "done"
