<!-- Argon consultation 2026-11-03T08:24:45Z, model gemini-4-argon-high, effort high; unaltered output except 33 local paths masked (AGENTS.md 4.2) -->

**Role:** REVIEWER

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| PO decision Q-48 alignment ([`PO_DECISION_RECORD_2026_11_03_Q48_ICAP_INGRESS_FROM_PROXIES.md`](file://<workspace-root>/docs/design/PO_DECISION_RECORD_2026_11_03_Q48_ICAP_INGRESS_FROM_PROXIES.md)) | **CONSENT** — Ratified record accurately documents the kube-proxy DNAT behaviour on HOST-A and the two-layer `/32` allowlist decision. |
| Pilot ICAP clients NetworkPolicy ([`35-pilot-icap-clients.yaml`](file://<workspace-root>/deploy/rwsafe/overlays/pilot/35-pilot-icap-clients.yaml), [`50-pilot-removed.yaml`](file://<workspace-root>/deploy/rwsafe/overlays/pilot/50-pilot-removed.yaml), [`kustomization.yaml`](file://<workspace-root>/deploy/rwsafe/overlays/pilot/kustomization.yaml)) | **CONSENT** — Selects only `<product>-icap` in `<product>`, `Ingress` only, TCP `1344` only, fails closed with [`ICAP_CLIENTS_PLACEHOLDER`](file://<workspace-root>/tools/deploy/manifest_check.py#L216), and deletes `rwsafe-icap-from-servicelb` in the pilot overlay. |
| Single-policy ICAP client bounds ([`check_icap_clients`](file://<workspace-root>/tools/deploy/manifest_check.py#L1171-L1210), [`icap_client_problem`](file://<workspace-root>/tools/deploy/manifest_check.py#L220-L238)) | **CONSENT** — Enforces namespace, exact pod selector, `Ingress` only, TCP `1344` without `endPort`, `ipBlock`-only peers without `except`, 1 to 8 non-duplicate `/32` RFC 1918 private addresses outside [`DIRECTORY_REFUSED_NETS`](file://<workspace-root>/tools/deploy/manifest_check.py#L169-L177), and value-free error messages. |
| Host helper no-echo & argument-free input ([`icap_clients.sh`](file://<workspace-root>/tools/pilot/icap_clients.sh), [`icap_clients.py`](file://<workspace-root>/tools/pilot/icap_clients.py)) | **CONSENT** — Refuses CLI arguments and root, reads with `read -rs`, strips `\r`, passes values only via stdin pipes, prints counts/rules only, and never passes `$HOME` paths on the process argument list. |
| Atomic nftables replacement & `y/n` loop ([`PILOT_RUNBOOK.md`](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L383-L439)) | **CONSENT** — Replaces the table atomically in one `nft -f -` transaction (`table` + `delete table` + `table`), clearing old set elements without a gap, and aborts cleanly on EOF without writing. |
| Gitignore coverage ([`.gitignore`](file://<workspace-root>/.gitignore#L51-L57)) | **CONSENT** — Ignores `icap-clients.env`, `.icap-clients.env.incoming`, `directory.env`, and `.directory.env.incoming`. |

---

### (2) DISSENT Table

| ID | File and line / symbol | What is wrong | Severity | Concrete correction |
|---|---|---|---|---|
| **D-01** | [`tools/deploy/manifest_check.py`](file://<workspace-root>/tools/deploy/manifest_check.py#L985-L999) (`check`), [`tools/deploy/test_manifest_check.py`](file://<workspace-root>/tools/deploy/test_manifest_check.py#L1078-L1175) (`IcapClientsPolicy`) | In a `pilot=True` check, `manifest_check.py` requires `directory_name` to exist (line 997) but does **not** require `icap_clients_name` (`<product>-icap-from-proxies`) to exist, does **not** refuse `<product>-icap-from-servicelb` if left in the pilot render, and does **not** bound selector-based ingress rules on other policies selecting `<product>-icap` (such as `<product>-icap`). If `35-pilot-icap-clients.yaml` is omitted or replaced by a selector policy, or `50-pilot-removed.yaml` drops the delete patch for `rwsafe-icap-from-servicelb`, `manifest_check.py` passes. | **P1** | In [`check`](file://<workspace-root>/tools/deploy/manifest_check.py#L985-L999), when `pilot` is true: (1) fail if `icap_clients_name` is missing from `policies`; (2) fail if `<product>-icap-from-servicelb` is present; (3) for every NetworkPolicy in `policies` with `Ingress` / `ingress` that selects `<product>-icap`, allow only `icap_clients_name`, `<product>-icap` (one rule, TCP `1344`, `from` only `podSelector`s `<product>-icap-e2e` and `<product>-icap-probe`), and `<product>-icap-metrics-from-scraper` (one rule, TCP `9401`). Add mutation tests in [`IcapClientsPolicy`](file://<workspace-root>/tools/deploy/test_manifest_check.py#L1078-L1175). |
| **D-02** | [`tools/pilot/render.py`](file://<workspace-root>/tools/pilot/render.py#L477-L488) and [lines 513-519](file://<workspace-root>/tools/pilot/render.py#L513-L519) (`main`) | When `ranges` or `addresses` is loaded and `--output` is omitted (`args.output is None`), `main` only checks `sys.stdout.isatty()`. Redirecting stdout to a file (`render.py ... > file.json`) makes `isatty()` false, writing the filled manifest with real host addresses/ranges without checking `_inside(..., mc.REPO_ROOT)` or [`write_output`](file://<workspace-root>/tools/pilot/render.py#L389-L410) (`O_NOFOLLOW`, regular-file check, `0600` mode). | **P1** | When `ranges or addresses` is truthy and `args.output is None`, require `sys.stdout` to be a pipe (`stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode)`, allowing in-memory test streams where `fileno()` raises `OSError`) and refuse any redirected regular file, terminal, device, or socket. Add a test in [`test_render.py`](file://<workspace-root>/tools/pilot/test_render.py). |
| **D-03** | [`tools/pilot/verify_firewall.sh`](file://<workspace-root>/tools/pilot/verify_firewall.sh#L93-L102) (`host_v4`), [`docs/operations/PILOT_RUNBOOK.md`](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L392-L398) (`ok_addr`), [`tools/pilot/test_verify_firewall.py`](file://<workspace-root>/tools/pilot/test_verify_firewall.py#L23-L104) | `verify_firewall.sh --table` (`host_v4`) only checks `ipaddress.ip_address(e).version == 4`, accepting unspecified, loopback, link-local, multicast, reserved/broadcast, cluster pod/Service ranges, and public IPv4 addresses. Step 11's `ok_addr` in `PILOT_RUNBOOK.md` also accepts the cluster pod/Service ranges and public IPv4 addresses, whereas step 11.5 (`icap_clients.sh`) refuses them via [`icap_client_problem`](file://<workspace-root>/tools/deploy/manifest_check.py#L220-L238). | **P1** | Apply the same validation in `ok_addr` (step 11 in both runbooks) and `host_v4` (`verify_firewall.sh --table`) as [`icap_client_problem`](file://<workspace-root>/tools/deploy/manifest_check.py#L220-L238): RFC 1918 private single IPv4 addresses only, outside loopback, link-local, multicast, reserved/broadcast, unspecified, and the cluster pod and Service ranges (plus `len(set(elem)) == len(elem)`). Build synthetic private test addresses at runtime in `test_verify_firewall.py` as `test_render.py` does. |
| **D-04** | [`tools/pilot/host_value_file.py`](file://<workspace-root>/tools/pilot/host_value_file.py#L56-L137) (`load`, `write`), [`tools/pilot/directory_range.sh`](file://<workspace-root>/tools/pilot/directory_range.sh#L45), [`tools/pilot/icap_clients.py`](file://<workspace-root>/tools/pilot/icap_clients.py#L60-L69) (`next_problems`) | (1) For `~/.config/<product>/pilot/<file>`, `.config` is `path.parent.parent.parent`: `icap_clients.sh` checks `"${HOME}/.config"`, but `directory_range.sh` line 45 omits `"${HOME}/.config"`, `host_value_file.write` line 111 checks only `(path, path.parent, path.parent.parent)`, and `host_value_file.load` checks `O_NOFOLLOW` only on `path` itself (not parent directories). (2) `icap_clients.next_problems` does not validate `accepted` (unlike `directory_range.next_problems` line 70 from PR 54 D-02). (3) `host_value_file.write` line 123 calls `os.write` once without looping on partial writes. | **P2** | (1) Add `"${HOME}/.config"` to the symlink loop in `directory_range.sh` line 45; in `host_value_file.load` and `write`, refuse symlinks on `(path, path.parent, path.parent.parent)` and (when named `.config`) `path.parent.parent.parent` (and check `path.parent.is_symlink()` in `render.write_output`). (2) In `icap_clients.next_problems`, refuse if `any(mc.icap_client_problem(a) for a in accepted)` or `len(set(accepted)) != len(accepted)`. (3) Loop `while data: data = data[os.write(fd, data):]` in `host_value_file.write`. |
| **D-05** | [`docs/operations/PILOT_RUNBOOK.md`](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L274-L280), [lines 551-568](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L551-L568), [line 583](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L583), [line 717](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L717) | (1) Step 8 mentions only `directory egress` (not `icap clients`), and Steps 12 and 14.3 state that applying Step 8's `~/pilot/app.json` is the same end state; if `~/pilot/app.json` was rendered before Step 11.5 (or 14.5), applying it resets `<product>-icap-from-proxies` (or `<product>-control-to-directory`) back to the placeholder. (2) Step 11.5 Undo (and Step 14.5 Undo) says to shred the `.env` file and "run step 2 again", but step 2's first command (`--check`) exits `1` when the file is absent. | **P2** | In Step 8, document the `icap clients` stderr line alongside `directory egress`; in Steps 12 and 14.3, note that `~/pilot/app.json` must be re-rendered after Steps 11.5 / 14.5 before applying; in Step 11.5 Undo and Step 14.5 Undo, specify running the `render.py ... \| kubectl apply --server-side -f -` command from step 2. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| None — PO decision Q-48 is ratified and all findings above are deterministic enforcement consistency fixes within its scope. | N/A |

---

### (4) Verdict

MERGE WITH CORRECTIONS

---

### (5) Instructions Received, Verbatim

1. `<RULE[<workspace-root>/AGENTS.md]>` (`AGENTS.md`, full text lines 1–187):
```markdown
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

2. `<USER_REQUEST>`:
```text
/plan REVIEW: second independent review of pull request 56 (AGENTS.md section 9, security-sensitive: the inline path's
ingress NetworkPolicy, the manifest checker, a host-side helper handling real addresses, a shared file module, the
firewall runbook block and its checker), branch `feature/pilot-icap-clients`
LENS: whether the ICAP pods admit TCP 1344 ONLY from the proxy addresses typed on the host (PO decision Q-48), with no
real address reaching the repository, a terminal, a log or an argument list, and whether the firewall step now replaces
its table atomically.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any way the ICAP ingress becomes broader than
the typed /32 addresses (selectors, ports, except, ranges, IPv6, the removed ServiceLB policy, other pilot policies),
any way a value leaks (helper, render, shared module, temp files, symlinks, modes, messages), any bypassable refusal,
any regression of PR 54's directory rules after the refactor, and any error in the firewall block (atomic replace, y/n
loop, validation) or in verify_firewall's 1-to-8 rule. Return exactly: (1) a CONSENT table (area, verdict), (2) a
DISSENT table (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3)
QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS
/ DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an
address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 8, 9)
- docs/design/PO_DECISION_RECORD_2026_11_03_Q48_ICAP_INGRESS_FROM_PROXIES.md
- deploy/rwsafe/overlays/pilot/ (every file), deploy/rwsafe/overlays/k3s/03-icap-service-lb.yaml and 04-networkpolicies-k3s.yaml
- tools/deploy/manifest_check.py and tools/deploy/test_manifest_check.py (the ICAP clients and directory rules)
- tools/pilot/host_value_file.py, icap_clients.py, icap_clients.sh, directory_range.py, directory_range.sh, render.py,
  test_render.py, verify_firewall.sh and its test
- .gitignore
- docs/operations/PILOT_RUNBOOK.md (steps 11, 11.5, 14.5)
```

3. `<ADDITIONAL_METADATA>` (`/plan` slash command metadata):
```text
The current local time is: 2026-11-03T11:16:19+03:00.

The user has mentioned some items in the form @[ITEM]. Here is extra information about the items that were mentioned by the user, in the order that they appear:

/plan is a [Slash Command]:
<PLAN>The user is requesting that you think and plan carefully before executing the upcoming task.
Carefully research the task, make sure that you and the user are aligned on the goals and requirements,
create a detailed implementation plan artifact, and get user approval on the plan before making any code changes (besides artifacts)
or running any modifying commands.

# Guidelines
- Establish a shared understanding of the task with the user. If there are any ambiguities, underspecified requirements,
or implicit assumptions, clarify them with the user before proceeding.
- Thoroughly research the codebase to establish a solid understanding of the relevant components, systems, dependencies, and architecture.
As you research, provide verbal updates of your research steps and thought process with the user, so they can follow along.
- Create an implementation plan artifact that outlines your proposed execution strategy.
Set request_feedback = true and user_facing = true in the ArtifactMetadata. The user will automatically
see any new and modified plans you create, so DO NOT re-summarize the plan.
- Only after the user explicitly approves the plan should you proceed to execution.
- Verify that your changes have the desired effects e.g. run unit tests, make sure code builds, etc. before claiming that the task is complete.
- After you've completed your task and verified that your solution works, create a walkthrough artifact to summarize your work.

# Planning Mode Artifacts
When in planning mode, you should create two special artifacts.

# Implementation Plan
Path: <Artifact Directory>/<plan_name>.md

**Purpose**: A technical design document to present your implementation plan to the user for feedback and approval.
After reading the document, the user should understand the key technical details of your plan, and be able to make an informed decision on whether to approve it.
This document should be very detailed, including code snippets, diffs, mermaid diagrams, verification strategies, and background information.

**Format**: Use the following format, omitting any irrelevant sections:

## [Goal Description]
Provide a brief description of the problem, any background context, and what the change accomplishes.

## User Review Required
Document anything that requires user review or feedback, for example, breaking changes or significant design decisions. Use GitHub alerts (IMPORTANT/WARNING/CAUTION) to highlight critical items.

## Open Questions
Any clarifying or design questions for the user that will impact the implementation plan. Use GitHub alerts (IMPORTANT/WARNING/CAUTION) to highlight critical items.

## Proposed Changes
Group files by component (e.g., package, feature area, dependency layer) and order logically (dependencies first). Separate components with horizontal rules for visual clarity.

### [Component Name]
Summary of what will change in this component with explicit code snippets and diffs. For specific files, Use [NEW] and [DELETE] to demarcate new and deleted files, for example:
#### [MODIFY] file basename
#### [NEW] file basename
#### [DELETE] file basename

## Verification Plan
Summary of how you will verify that your changes have the desired effects.

### Automated Tests
Exact commands to run automated tests

### Manual Verification
Instructions for what the user should manually verify.

# Walkthrough
Path: <Artifact Directory>/walkthrough.md

**Purpose**: After completing work, summarize what you accomplished. Update an existing walkthrough for related follow-up work rather than creating a new one.

**Document**:
- Changes made
- What was tested
- Validation results

Embed screenshots and recordings to visually demonstrate UI changes and user flows.</PLAN>
```
