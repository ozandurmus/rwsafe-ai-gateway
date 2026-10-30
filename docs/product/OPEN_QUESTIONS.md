# Open questions for the Product Owner

**Status:** LIVE. Each question: what is undecided, the options, the architect's recommendation, what blocks on it. The
first eight are the brief's own (10.6). A decision becomes a `docs/design/PO_DECISION_RECORD_*.md` and the question moves
to the "Decided" table. Chat answers in Turkish are quoted in the record; the question text here stays English.

## A. The brief's known questions (10.6)

| Id | Question | Options | Recommendation | Blocks |
|---|---|---|---|---|
| Q-1 | SSE responses: strict inline blocking on REQMOD plus sliding-window RESPMOD with abort, instead of buffering? | (a) as proposed; (b) buffer and inspect whole responses; (c) REQMOD only, no RESPMOD | **(a)** (council: yes). (b) breaks IDE/CLI usability and memory bounds; (c) loses the response-side detection. Note: a streamed response can only be aborted, never redacted (ADR-005) | ICAP spec §4.4, ADR-005 freeze |
| Q-2 | LLM API gateway on 443 through its own host name (`ai-api.<corp-domain>`)? | (a) 443 by host name; (b) its own TCP port | **(a)** (council: yes): no new firewall exception, SDKs take a URL. The brief asked for a port, so this is a formal choice | ADR-003, PORTS §3 |
| Q-3 | Disk watermark: above it stop persisting raw bodies, keep enforcing and keep metadata? | (a) 75 % raw off, 85 % redacted off; (b) another pair of numbers; (c) no breaker | **(a)**. HOST-A is at 80 % today, so raw capture starts off | CAPACITY §2, ADR-009 |
| Q-4 | MVP capture mode | (a) PO decision as written: content capture on from day one, raw included where policy allows; (b) privacy seat: metadata + verdict + redacted content from day one, raw content behind a separate key and an approval record per platform/group | **(b)**, which keeps the PO's "capture on from day one" (redacted content is content) and adds the raw layer when the notice, the DPO's approval record and the disk allow it. With HOST-A at 80 %, (a) cannot persist raw bodies anyway until the watermark is cleared. Both options are fully designed (ADR-009) | ADR-009, PIA, ROADMAP MVP |
| Q-5 | Raw-content access: who approves, who is the DPO, retention days per class | approver pairs: `security_admin` + `privacy_officer` (recommended) or two `security_admin`s; DPO identity: a named person or role in the directory; retention: C1/C2/C6 400 d, C3 90 d, C4 30 d, C7 10 y, C10 14 d, C12 scope + 400 d (recommended) | as listed; the DPO is a directory group, not a person, so leave is covered | RAW_CONTENT_ACCESS, DATA_CLASSES |
| Q-6 | Scope of people and use: BYOD, contractors, personal AI use | personal use on the corporate network: (a) blocked, event only; (b) allowed, not captured; contractors/BYOD: (c) in scope only on managed devices; (d) out of scope | **(a) + (c)**: blocked with a coaching page, the block event stored without content; unmanaged devices are governed by tenant settings only | ADR-007 rollout, OUT_OF_SCOPE §4 |
| Q-7 | Models and regions allowlist per data class | a table: class × platform × model family × region → allowed? | start with: public data: all enterprise tenants; internal data: enterprise tenants with DPA; customer data, banking secret, special-category: **no external model at all** until a documented contract and the regulator reading in REGULATORY_MAPPING say otherwise | policy registry seed, gateway allowlist |
| Q-8 | Cloud-side agents: accept them as out of gateway scope, governed by tenant settings? | (a) yes with the compensating controls in OUT_OF_SCOPE §1; (b) block their consoles until an inline path exists | **(a)**; (b) blocks sanctioned tools without gaining visibility | OUT_OF_SCOPE, PLATFORM_MATRIX |

## B. Questions raised by the design

| Id | Question | Options | Recommendation | Blocks |
|---|---|---|---|---|
| Q-9 | MVP login method for the admin UI | (a) LDAP/AD bind + group binding (neXus parity, works on HOST-A today); (b) SAML 2.0 SP (corporate standard); (c) both from day one | **(a) for the MVP, (b) added before the corporate-platform stage**; the group → role binding is shared | ADR (identity), stack matrix |
| Q-10 | rwsafe's data-plane PriorityClass (1000) is above neXus's `ui2-low` (−100, packet analysis) and below every other neXus class. Acceptable? | (a) yes; (b) put all of rwsafe below −100 | **(a)**: packet analysis is neXus's declared lowest-priority batch work; the brief's rule targets neXus's service workloads | ADR-001, AC-1 |
| Q-11 | neXus's own limits over-commit the node (25 CPU, 74 GiB on 16/62). Report only, or ask the neXus session to right-size? | (a) report; (b) neXus change | **(a) now**; rwsafe protects neXus by being evicted first; a neXus change is the neXus session's call | — |
| Q-12 | Off-host backup target for rwsafe's encrypted backups (and neXus's artefact store, still open on the neXus side) | a corporate backup share or object store named by the PO | name one before the pilot; until then backups stay on HOST-A inside the platform set | ADR-002 §6 |
| Q-13 | The neXus ingress change ends bare-IP access to the neXus console and requires DNS or hosts entries. Approve, and when should the neXus PR be delivered? | (a) before the rwsafe pilot (needed for host routing); (b) later with the corporate DNS names | **(a)**, with the 404 default backend, in a quiet window; operators informed | ADR-003 |
| Q-14 | ProxySG REQMOD fail setting for the AI category: fail-closed from pilot start, or fail-open for two weeks? | (a) closed from start; (b) open for two weeks, then closed | **(b)**: measure rwsafe's availability on real traffic first; the switch is a recorded ProxySG change | ADR-010, ROADMAP phase 1 |
| Q-15 | Build tool: Gradle (brief, neXus parity, lockfiles) or Maven (corporate standard)? | (a) Gradle with a Maven-portability check; (b) Maven | **(a)** | ADR-011, stack matrix |
| Q-16 | Persistence: jOOQ (brief) or Spring Data JDBC (corporate)? | (a) jOOQ; (b) Spring Data JDBC | **(a)** for the trigger-audit pattern and neXus parity | ADR-011 |
| Q-17 | ARK naming and branching conventions: please supply the document so repository, branch and namespace names can follow it | — | adopt what is compatible with GitHub and k3s now; record deviations | stack matrix |
| Q-18 | Build the chained forward proxy (3128) after phase 0 if a sanctioned WebSocket flow needs inspection? | (a) yes if demand is shown; (b) never, refuse WebSocket to AI hosts | **(a)** conditional | ADR-004, H-9 |
| Q-19 | Agent path timing and scope | (a) browsers only (MV3 extension) first; (b) IDE/CLI endpoint agent first; (c) both after the MVP | **(a) after the MVP**, measured by the spike; (b) follows if the trust matrix shows CLI clients off-net are common | ADR-006, ROADMAP |
| Q-20 | Ask Broadcom (support case) whether Cloud SWG can forward the AI category to an on-prem ICAP server or connector | — | yes, in phase 0, by the proxy team | ADR-006 |
| Q-21 | Which vendor tenant headers can the proxy team deploy in phase 1 (Entra, Google, ChatGPT)? And is Entra tenant restrictions v2 already in use? | — | all three on the pilot group's policy layer; v2 status to be confirmed | ADR-007, ROADMAP phase 1 |
| Q-22 | ML prompt-injection tier: asynchronous only (MVP) or inline later if CPU allows? | (a) async only; (b) inline with a bounded budget after measurement | **(a) for the MVP** | ADR-008 |
| Q-23 | Customer-number formats and the Turkish name dictionary source | formats: the PO supplies regex-shaped rules (no samples); names: a public list | as stated | detector library, masking layer 4 |
| Q-24 | Frontend HTTP client: Axios (corporate) or fetch wrapper (neXus) | minor | decide at the first frontend commit; Axios acceptable | — |
| Q-25 | Which XDR product runs on the endpoints (for agent coexistence) | — | name it when the agent phase starts | ADR-006 |
| Q-26 | Image signing tool and the corporate proxy path for it (cosign/Sigstore recommended) | — | cosign with a key in a Secret; keyless is not possible offline | SSDF §6 |
| Q-27 | SNMP: poll 1161/udp, or add a host firewall redirect 161→1161 (exception H-3)? | (a) 1161; (b) redirect | **(a)** | HARDENING H-3 |
| Q-28 | Pilot with plain ICAP on 1344 for up to 60 days while Secure ICAP certificates are issued (exception H-2)? | (a) yes; (b) Secure ICAP from day one | **(b) if the proxy team can issue the client certificate before the pilot; otherwise (a)** | HARDENING H-2 |
| Q-29 | Residual risk acceptance: host root and cluster admin can read Secrets and PVCs (no HSM); streaming responses cannot be redacted; pinned apps and off-net users invisible until the agent phase; MV3 blocking is best-effort | sign or request mitigation | sign for the pilot, revisit before production | THREAT_MODEL §10 |

## C. Decided

| Id | Decision record | Date |
|---|---|---|
| — | — | — |
