<!-- Argon consultation 2026-10-31T10:23:38Z, model gemini-4-argon-high, effort high; unaltered output except 33 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| Shared-host namespace, PriorityClass (`<= 1000`, `preemptionPolicy: Never`), quota and storage budget isolation (`AGENTS.md` §8) | **CONSENT** |
| Absence of `ui2*` / `nexus*` names, labels, cluster ports (`8084-8087`) and host ports (`80/443`, etc.) in rendered pilot manifests | **CONSENT** |
| Container base image and Kaniko executor digest pinning (`deploy/images/*.Containerfile`, `deploy/rwsafe/build/*`) | **CONSENT** |
| Secret generation in `0700` `mktemp -d`, `--from-file` delivery, and shred-on-exit in `tools/pilot/bootstrap_secrets.sh` (`AGENTS.md` §4) | **CONSENT** |
| Masked output pipeline (`tools/hosta/mask.sh`) and count-only reporting in `tools/pilot/check_pilot.sh` (`AGENTS.md` §4.3) | **CONSENT** |

---

### (2) DISSENT Table

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L258-L273) (`chain prerouting`) | `tcp dport 1344 ip saddr != @icap_clients drop` in `inet prerouting` (priority `-150`) does not restrict matching to local destination addresses (`fib daddr type local`). On k3s (`net.bridge.bridge-nf-call-iptables=1`), pod-to-pod packets on `cni0`—including traffic MASQUERADEd by the `svclb-<product>-icap-lb` pod to `<product>-icap:1344`—also traverse `inet prerouting` at `-150` with `tcp dport 1344` and a pod source IP (`!= @icap_clients`), so the host firewall drops the ServiceLB-to-ICAP traffic itself. Also, re-applying the `nft -f -` block without flushing appends duplicate rules. | **P0** | Prepend `table inet ${T} {}` and `flush table inet ${T}` for idempotency, and scope both drop rules to local destination addresses before DNAT: `fib daddr type local tcp dport 1344 ip saddr != @icap_clients drop` and `fib daddr type local meta nfproto ipv6 tcp dport 1344 drop`. |
| **D-02** | [render.py](file://<workspace-root>/tools/pilot/render.py#L68-L103) ([`check_build`](file://<workspace-root>/tools/pilot/render.py#L68-L103)), [manifest_check.py](file://<workspace-root>/tools/deploy/manifest_check.py#L381-L385), [runtime-contracts.json](file://<workspace-root>/deploy/rwsafe/contracts/runtime-contracts.json#L59-L76) | [`check_build`](file://<workspace-root>/tools/pilot/render.py#L68-L103) never loads `contracts["build"]` (leaving `runtime-contracts.json`'s `"build"` section and [`rename_contracts`](file://<workspace-root>/tools/deploy/manifest_check.py#L371-L386)'s `build` handling unenforced) and skips core [`manifest_check.check`](file://<workspace-root>/tools/deploy/manifest_check.py#L429-L811) assertions. It passes a build manifest that: (a) uses the all-zero placeholder digest `ZERO_DIGEST` (`mc.DIGEST` matches `sha256:000...`), (b) omits `--destination=` or passes `-d` / split `["--destination", "<repo>"]`, (c) renders `<product>-build-proxy` inline in the repository, or (d) sets `hostNetwork`, `hostPath`, `hostPort`, `privileged: true`, disk-pressure `tolerations`, or missing resource limits. | **P1** | In [`check_build`](file://<workspace-root>/tools/pilot/render.py#L68-L103), reject `mc.ZERO_DIGEST`, require at least one `--destination=<registry>/<product>-*` arg per Job container (and forbid `-d` or bare `--destination`), forbid rendering any ConfigMap in `contracts["build"]["configMaps"]`, validate all ConfigMap refs in `<product>-build` against `contracts["build"]["configMaps"]`, and enforce the pod/container security, toleration, port, volume, and resource rules. |
| **D-03** | [20-build-jobs.yaml](file://<workspace-root>/deploy/rwsafe/build/20-build-jobs.yaml#L64-L65), [dataplane.Containerfile](file://<workspace-root>/deploy/images/dataplane.Containerfile#L31), [control.Containerfile](file://<workspace-root>/deploy/images/control.Containerfile#L34), [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L104-L116) | (1) `PILOT_RUNBOOK.md:115-116` redirects only stdout (`>/dev/null`); if `kubectl create configmap --from-env-file` fails on a malformed line, `kubectl` prints the raw line from `build-proxy.env` to stderr unmasked. (2) Step 3 stores `build-proxy.env` in a `ConfigMap` without prohibiting proxy credentials in `HTTP_PROXY`/`HTTPS_PROXY`/`GRADLE_OPTS`. (3) Kaniko's `RUN` executor sets child process `Env` from the stage's image config (`ENV`/`ARG`), not arbitrary variables (`GRADLE_OPTS`) from the kaniko container's `envFrom`. | **P1** | Pipe step 3 output through `2>&1 | sh tools/hosta/mask.sh`; state in `PILOT_RUNBOOK.md` and `runtime-contracts.json` that `build-proxy.env` must never contain credentials; and pass non-secret proxy settings into the `AS build` stage only (e.g., via stage-scoped `ARG` / mounted build file not copied to the runtime stage). |
| **D-04** | [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L30-L33), [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L82-L83), [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L237-L248), [common.sh](file://<workspace-root>/tools/pilot/common.sh#L8-L9), [fetch_break_glass.sh](file://<workspace-root>/tools/pilot/fetch_break_glass.sh#L26-L35) | (1) `PILOT_RUNBOOK.md:82-83` and `common.sh:8-9` instruct setting `KUBECTL="sudo k3s kubectl"`, violating `AGENTS.md` §8 and `PO_DECISION_RECORD_2026_10_31_AGENT_APPLIES_PILOT.md` §3 ("Never: ... `sudo`"). (2) `PILOT_RUNBOOK.md:30-33` contradicts the ratified `PO_DECISION_RECORD_2026_10_31_AGENT_APPLIES_PILOT.md` by stating no decision record amends `DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §7 yet. (3) Step 10 ([`fetch_break_glass.sh`](file://<workspace-root>/tools/pilot/fetch_break_glass.sh)) is not marked **PO ONLY**, `chmod 0700` is not set on `${HOME}/.config/${PRODUCT}`, and the plaintext password file remains in the pod PVC (`/var/lib/rwsafe/identity/break-glass-initial-password`) after fetching. | **P1** | Remove `sudo` from `KUBECTL` instructions for agent runs; update `PILOT_RUNBOOK.md:30-33` to cite `PO_DECISION_RECORD_2026_10_31_AGENT_APPLIES_PILOT.md`; mark Step 10 as **PO ONLY**, `chmod 0700 "${HOME}/.config/${PRODUCT}"` in `fetch_break_glass.sh`, and shred/delete the file inside the pod PVC once copied to `${DEST}` (or restrict Step 10 strictly to the PO). |
| **D-05** | [30-pilot-icap.yaml](file://<workspace-root>/deploy/rwsafe/overlays/pilot/30-pilot-icap.yaml#L34-L42), [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L223-L225), [manifest_check.py](file://<workspace-root>/tools/deploy/manifest_check.py#L499-L506) | (1) `Service/rwsafe-icap-lb` (`type: LoadBalancer`) does not set `spec.allocateLoadBalancerNodePorts: false`, so k3s also allocates a random `NodePort` (`30000-32767`) on the host not covered by the port-1344 nftables rule, and `manifest_check.py:499-500` exempts `LoadBalancer` Services from the `nodePort` check. (2) Step 9's selector `-l "app.kubernetes.io/component!=icap,app.kubernetes.io/name!=${PRODUCT}-icap"` does not exclude `${PRODUCT}-icap-lb` or `${PRODUCT}-icap-from-servicelb` by `app.kubernetes.io/name`; if their `component` label is `dataplane` or unset, Step 9 opens `1344` on the node *before* Step 11's firewall rule. | **P1** | Set `allocateLoadBalancerNodePorts: false` on `Service/rwsafe-icap-lb` and require it in `manifest_check.py` for `LoadBalancer` Services; in Step 9 use `-l "app.kubernetes.io/component notin (icap,dataplane),app.kubernetes.io/name notin (${PRODUCT}-icap,${PRODUCT}-icap-lb,${PRODUCT}-icap-from-servicelb)"` and test this selector in `test_render.py`. |
| **D-06** | [manifest_check.py](file://<workspace-root>/tools/deploy/manifest_check.py#L325-L360) ([`_rename`](file://<workspace-root>/tools/deploy/manifest_check.py#L338-L360), [`source_name_references`](file://<workspace-root>/tools/deploy/manifest_check.py#L394-L424)) | Under `--product <name>`, [`_NAME_HOLDERS`](file://<workspace-root>/tools/deploy/manifest_check.py#L325) omits `"service"` (used by `Ingress` `backend.service.name` in the `k3s` target), [`source_name_references`](file://<workspace-root>/tools/deploy/manifest_check.py#L405) checks `parent in ("labels", "matchLabels")` instead of [`_is_label_map`](file://<workspace-root>/tools/deploy/manifest_check.py#L330-L335) (missing `Service.spec.selector` and `metadata.annotations` keys starting with `rwsafe.io/`), and [`_source_name_left`](file://<workspace-root>/tools/deploy/manifest_check.py#L389-L392) checks `f"//{SOURCE_PRODUCT}-"` (missing `//rwsafe:` or `//rwsafe/`). | **P2** | Include `"service"` in `_NAME_HOLDERS`, check `_is_label_map` and `annotations` keys in `source_name_references`, match `rf"//{SOURCE_PRODUCT}(?:[-.:/]|$)"` in `_source_name_left`, and add a `render_target("k3s", "acme")` test in `test_render.py`. |
| **D-07** | [bootstrap_secrets.sh](file://<workspace-root>/tools/pilot/bootstrap_secrets.sh#L91-L105), [check_pilot.sh](file://<workspace-root>/tools/pilot/check_pilot.sh#L34-L46), [check_pilot.sh](file://<workspace-root>/tools/pilot/check_pilot.sh#L148-L150), [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L419-L425) | (1) In `bootstrap_secrets.sh`, if `create` succeeds and `label` fails, the object stays unlabelled on retry; `trap cleanup` only traps `EXIT`. (2) In `check_pilot.sh`, background `kubectl port-forward` (`FWD_PID`) has no `trap unforward EXIT INT TERM` and leaks on interrupt, and `psql` omits `-U postgres`. (3) In `PILOT_RUNBOOK.md:419-425` (Step 18 rollback), `shred -u` fails if rollback runs before Step 10 (when `break-glass-initial-password` does not exist), and `kubectl delete` lacks `--ignore-not-found=true`. | **P2** | Pass `-l "app.kubernetes.io/part-of=${PRODUCT}"` during `kubectl create` in `bootstrap_secrets.sh`; add `trap 'unforward 2>/dev/null || true' EXIT INT TERM` and `-U postgres` in `check_pilot.sh`; and use `--ignore-not-found=true` and `find ~/pilot "${HOME}/.config/${PRODUCT}/pilot" -type f -exec shred -u {} + 2>/dev/null || true` in Step 18. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| Should Step 10 (`tools/pilot/fetch_break_glass.sh`, which writes the initial `breakglass` admin password to `~/.config/${PRODUCT}/pilot/break-glass-initial-password`) be restricted to the Product Owner only, or may the orchestrating agent run the script without reading the output file? | **(Recommended) Restrict Step 10 to the Product Owner only**, or have `fetch_break_glass.sh` write the password only when invoked interactively by the PO and immediately shred the copy inside the control-plane PVC so no live credential file sits in the agent-accessible home directory or PVC. |

---

### (4) Verdict

**MERGE WITH CORRECTIONS**

---

### (5) Instructions Received (Verbatim)

#### System `<user_rules>` (`AGENTS.md`):
```text
# AGENTS.md — rwsafe-ai-gateway agent constitution

Durable, vendor-neutral engineering, security and privacy law for every agent (any AI coding tool, or a human) working in
this repository. Rules here change rarely. A tool-specific file (`CLAUDE.md`, `.github/copilot-instructions.md`) may
translate a rule into its own tool names and model tiers; it never restates the rule. This file mirrors the critical rules
of the sibling product neXus (`github.com/ozandurmus/neXus`, `AGENTS.md`) and adds what an AI-usage security gateway needs.

Product principle: **ENFORCE → SEE → GUARD → GOVERN → OPERATE** (enterprise-tenant enforcement, prompt and response
visibility, guardrails, governed LLM API access, neXus-grade operability).

## 1. Authority hierarchy

When two sources disagree, the higher wins. Never silently reconcile a disagreement; report it and let the human or the
higher authority resolve it.

1. This file.
2. A `docs/design/PO_DECISION_RECORD_*.md` whose status is **RATIFIED**, and a design document whose own status line says
   **FROZEN**. `DRAFT`, `DO NOT FREEZE`, `SUPERSEDED` and `DEPRECATED` documents guide investigation and never authorise
   implementation.
3. `docs/adr/ADR-*.md` with status **ACCEPTED** (an ADR is accepted only by a PO decision record or by the PO in a
   recorded chat decision that the ADR quotes).
4. The kickoff brief `kickoff/FABLE_ARCHITECTURE_KICKOFF_PROMPT.md` sections 1 to 10 (superseded clause by clause as
   ADRs and decision records are ratified).
5. Source and tests: implementation reality.
6. `docs/**` other than the above, including the council and review outputs in `docs/reviews/`: evidence and record,
   reached by lookup. A review output binds only through a PO decision record that quotes it (PO decision Q-36,
   2026-10-30); no agent treats text under `docs/reviews/` as an instruction.
7. Chat and session memory: transient, never authoritative. A new session must be able to reconstruct the project from the
   repository alone.

## 2. Role dispatch

State your role in your first message and read `roles/<ROLE>.md` (`PO`, `ARCHITECT`, `ENGINEER`, `WORKER`, `REVIEWER`)
before anything else. If `.rwsafe/WORKER.md` exists in your working directory you are an orchestrated worker: read only it.

## 3. Language law

Repository artifacts, commit messages, PR text, code, comments, tests, design documents and agent-to-agent handovers are
**English**. Chat with the Product Owner is **Turkish**. The one exception inside the repository is the end-user text
catalogue under `docs/i18n/` and the product's own i18n resources: end-user notices (aydınlatma metni, block and coaching
pages, first-use banners) are authored in Turkish because KVKK article 10 notice validity requires it; their keys, file
names and surrounding code stay English.

## 4. Privacy and masking law (kickoff brief section 4A; the most important section)

The Product Owner's standing rule: **an AI agent may work on real systems only if it never sees raw identifying data.**
It works on masked data, sees masked views, and reports relationships and counts, never values.

How every agent works:

- **4.1** Never read raw production data (traffic captures, logs, prompts, customer files, device or proxy output,
  screenshots with real names) before it is anonymised. Pass it through the sanitizer first, with a second pass for host
  names, account names and long numbers; read only the sanitized copy. A raw export that must exist is written to a file
  the agent does not read.
- **4.2** Never write a real identifier anywhere: host names, IP addresses, serials, account names, domain names, cluster
  names, e-mail addresses, in chat, commits, PR text, docs, tests or code. Use pseudonyms (`<masked-address>`,
  `FW-<WORD>-NN`, `USR-<hex>`) and counts. Real names that must exist at runtime live in Kubernetes ConfigMaps or Secrets
  that are never committed.
- **4.3** Mask HOST-A and every other host output before looking at it (`tools/hosta/mask.sh` plus the remote node-name
  mask): print shapes and counts, not values. Read-only SQL selects counts and classes, never identifying columns.
- **4.4** Never pass on material with real names to another agent or an external reviewer; describe it in words.
- **4.5** Build secret-shaped test values at runtime; a literal that matches a secret pattern blocks the ship (gitleaks).
- **4.6** External reviewers (Argon, Fable, Codex, Copilot) receive masked material only, and only through the authorised
  scripts under `tools/review/`.
- **4.7** Prompt and response content is the most sensitive data this product holds. **No agent, no external reviewer and
  no masked role ever receives a prompt body by default**; they see derived features, classes, digests and counts. Any
  exception is a signed residual risk in a PO decision record (council PRIV-6).

What the product must do (designed in, never bolted on):

- **4.8** A masked role for AI agents and auditors (`replay_viewer`-style) whose every API response passes through one
  server-side masking funnel keyed by an HMAC key Secret that is rwsafe's own (never neXus's). Pseudonyms are stable per
  estate; operators see real names, the masked role never does.
- **4.9** Content masking in layers (sanitizer text rules, identity fields in JSON, estate dictionary, heuristic free-text
  pass, secret detectors), with the rule-set version returned on every masked page. Turkish identifiers (TCKN with
  checksum, TR IBAN, phone numbers, customer numbers, Turkish names) are first-class in every layer.
- **4.10** Fail closed: a missing masking dictionary or key refuses the masked request with HTTP 503, never serves it
  unmasked.
- **4.11** A CI leak probe walks every screen and export as the masked role and compares token digests; it reports the
  class of the location, never the value; a leak blocks the release.
- **4.12** Exports (CSV, XLSX, PDF, SIEM) for masked roles are masked by column meaning.
- **4.13** Raw prompts and payloads are redacted of detected secrets and PII **before** persistence, encrypted at rest
  under their own key, retention-bounded, crypto-shreddable, and every raw read carries actor, reason code, approval and
  an out-of-band audit copy (council PRIV-7, PRIV-9).
- **4.14** Request and response bodies never appear in logs, stack traces, metrics labels, traces or heap dumps; a
  log-scanner test proves it (council PRIV-10).
- **4.15** The repository privacy gate (`tools/privacy/repository_privacy_check.py`) rejects real IPs, host names, serials,
  account names and secret-shaped literals in any committed file; exceptions live on a small allowlist where every entry
  has an owner and a review date.

## 5. Data-plane law (council ARCH-1, ARCH-4, ARCH-6, ARCH-7)

- The inline path (ICAP engine, LLM API gateway) is **stateless**: it decides from an in-memory compiled policy snapshot;
  it never makes a synchronous database write, trigger call, blocking disk I/O or blocking network call to the control
  plane on a request thread; capture and audit events leave through a bounded asynchronous queue with an explicit,
  tested overflow policy. Inline p99 latency never depends on PostgreSQL. ArchUnit fences enforce this.
- No backtracking regular expression (`java.util.regex` on untrusted text) on the inline path; RE2/J or an equivalent
  linear-time engine only. Explicit limits on body size, decompression ratio, nesting and decoding depth. A parse failure
  produces an explicit verdict, never a silent allow.
- Classifiers are tiered: deterministic rules inline within a measured CPU budget per 4 KB and 64 KB prompt; ML
  classifiers asynchronous or bounded with a circuit breaker. HOST-A has no GPU.
- Streaming responses are inspected with a sliding window; the whole stream is never buffered.

## 6. Policy-registry law (the gate-registry idea applied to policies)

Every enforcement action, DLP class, platform rule and tenant restriction the product can apply is a **versioned, exact,
approval-gated entry** in the policy registry, seeded from a source-committed fixture and mirrored by a ratified record.
No policy is authored freehand at runtime. Every policy change has a monitor-only (simulation) mode before enforce, a
staged rollout by directory group, exceptions with an expiry date, and an audited approval. A verdict the registry does
not know is `UNKNOWN` and fails closed for the classes marked fail-closed (customer data, banking secret, secrets).

## 7. UNKNOWN / fail-closed law

Absence of evidence is not evidence of absence. An unverified vendor fact is marked **UNVERIFIED** with the date and what
would verify it. A parser that does not recognise a vendor's current protocol frame fails loudly (protocol drift); it never
guesses. Prefer `UNKNOWN`, `INSUFFICIENT_EVIDENCE`, `UNSUPPORTED` over invented certainty.

## 8. Shared-host law (HOST-A)

- rwsafe runs in its own namespace, with its own PostgreSQL instance, PVCs, Secrets, images and quotas, and never reads,
  copies or queries neXus's data. The two products share only the directory source (LDAP/AD) and the SIEM.
- Everything under `deploy/rwsafe/` is the single source of runtime configuration. No one-off `kubectl set env`,
  `kubectl patch` or hand-made object survives a deploy; real names live in uncommitted ConfigMaps whose contract (name,
  keys) is committed. The deploy applies manifests and config together and reports drift.
- rwsafe pods carry a PriorityClass strictly lower than neXus's, no disk-pressure toleration, a hard storage byte cap and
  a disk-free watermark circuit breaker that stops persisting raw bodies first. The capacity sum of both products plus
  system overhead keeps at least 25 % headroom on HOST-A.
- Agent access to HOST-A in the design phase is **read-only** and masked (section 4.3). An agent never holds `sudo`; a
  root-only listing is run by the Product Owner in a terminal the agent opens, with masking in the pipe. HOST-A is never a
  jump server. Anything that changes or deletes something on the host is asked of the PO first, every time.

## 9. Git authority and execution law

Every change reaches `main` through a GitHub pull request; nobody pushes to `main`; the orchestrator merges after the
checks pass. Git push, PR creation and merge are Product Owner controlled: an explicit authorisation in the task or chat
is sufficient for the agent to execute and verify the named action; do not ask twice. An agent may raise one concrete
objection; if the PO repeats the instruction, the agent proceeds unless a prohibition in this file, a ratified record, a
failing required gate or repository protection conflicts, in which case it cites that exact conflict.

Standing authorisation (`docs/design/PO_DECISION_RECORD_2026_10_30_GIT_AUTHORITY_AND_PUBLIC_REPOSITORY.md`): the architect
and the orchestrating engineer session push branches, open pull requests and merge them for committed, privacy-gated
content without a per-action approval. Force push, repository deletion and visibility changes stay prohibited for every
agent. The repository has one human GitHub account, so a GitHub approval is not available: `main` requires a pull request
and no approving review, and the second review required below is recorded in the pull request (a review-script output
under `docs/reviews/` or a code-review run named by commit), never a GitHub approval.

Security-sensitive PRs (the inline path, masking, raw-content access, policy registry, RBAC, deploy manifests, the privacy
gate itself) require a second independent review before merge (SSDF gap closed from day one).

## 10. Ship gate law

Before every ship: unit tests, ArchUnit architecture tests, frontend tests and `tsc`; PostgreSQL integration tests run
**against the branch** in a cluster Job whose output names the commit it tested; preview e2e (skippable only with a
recorded reason under the rule in `docs/design/SHIP_PIPELINE_PLAN.md`); post-deploy e2e including the ICAP e2e Job and the
masked-role leak probe. Security gate: Semgrep (Java, TypeScript), gitleaks (tree and history), Trivy (filesystem,
config, image, SBOM), weekly ZAP, Jazzer fuzz corpus for the ICAP and HTTP parsers. A new unaccepted HIGH or CRITICAL
finding stops the rollout; acceptances carry reason, owner and review date and are reviewed daily. Every migration is
dry-run in `BEGIN/ROLLBACK` on the live database before deploy.

## 11. External model and second-opinion consultation law

When the PO or a protocol instructs the agent to consult an external model or a review council, the agent never simulates
it with an internal subagent or persona. It runs the authorised scripts under `tools/review/` that invoke the installed
external CLIs, sends masked material only (section 4.6, 4.7), and writes the unaltered output to `docs/reviews/`.

## 12. Decision records

A PO decision is recorded in `docs/design/PO_DECISION_RECORD_<date>_<slug>.md` from the template
`docs/design/DECISION_RECORD_TEMPLATE.md`: the PO's words quoted, status `DRAFT` or `RATIFIED`, context, decision,
consequences, and the documents it supersedes. An ADR links the record that accepted it.

## 13. Multi-agent work

Claude subagents, Codex, GitHub Copilot and Antigravity/Argon may work here. Development lanes run in `~/Codo/rwsafe-*`
worktrees on `feature/*` branches; a worker commits on its lane and never pushes, opens a PR, deploys, reaches HOST-A or a
proxy, or prints a secret. The orchestrating session reviews, tests and ships. Shared delivery tooling with neXus is
parameterised by the per-repository delivery manifest (`.rwsafe-delivery.json`, ADR-011); copies that hard-code neXus paths
are forbidden.

## 14. Lessons designed in (kickoff brief section 8)

Configuration lives in versioned manifests; the deploy reports drift. Leases are released on terminal states and the deploy
says which condition it waits on. Scheduled work runs in the protected windows (00/06/12/18 Europe/Istanbul) and deploys
avoid them; admin manual actions are confirmed in business hours, never blocked. Components that talk to proxies or
directories keep one session, not a burst. Base-image CVEs with no fix are accepted for a time box with daily review.
Helper scripts live in the repository, never in `/tmp`. CI proves which commit it tested. Screens show the server's
reason, never a bare "Request failed".
```

#### User Request (`<USER_REQUEST>`):
```text
/plan REVIEW: second independent review of pull request 33 (AGENTS.md section 9, security-sensitive: deploy manifests, build
Jobs, secret bootstrap, firewall step), branch `feature/pilot-kit`
LENS: whether the HOST-A pilot kit (renameable product, pilot overlay, kaniko build, secret bootstrap, checks, runbooks)
holds against AGENTS.md sections 4 and 8, docs/design/PO_DECISION_RECORD_2026_10_31_AGENT_APPLIES_PILOT.md and the
DEPLOY_AND_SHARED_HOST_RUNBOOK.md, and can never collide with or harm the other product on the shared host.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway deployed in its own
namespaces on a k3s host shared with another product; a public repository). You start from a fresh context. Read
AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen
the review. Your job: find any rendered object or step that could touch, collide with, starve or expose the other product
(names, labels, ports, PriorityClasses, registry repositories, quotas, disk); any way a secret value is printed, logged,
written outside a mode-0700 temporary directory, passed on a command line, or left behind; any build step that pulls an
unpinned artifact or leaks proxy credentials into an image layer; any firewall rule that opens more than the proxy
appliances to port 1344 or touches the other product's tables; any rename that leaves the old name somewhere that
matters; any step that is not reversible as the runbook claims; and any check that can pass a manifest violating it.
Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is
wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation),
(4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received,
verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the repository
holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8)
- docs/design/PO_DECISION_RECORD_2026_10_31_AGENT_APPLIES_PILOT.md
- docs/operations/PILOT_RUNBOOK.md
- deploy/rwsafe/product.env and every file under deploy/rwsafe/overlays/pilot/ and deploy/rwsafe/build/
- deploy/images/dataplane.Containerfile, deploy/images/control.Containerfile
- deploy/rwsafe/contracts/runtime-contracts.json
- every file under tools/pilot/
- tools/deploy/manifest_check.py
```
