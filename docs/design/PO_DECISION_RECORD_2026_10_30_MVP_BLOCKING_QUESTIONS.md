# PO decision record 2026-10-30: MVP-blocking open questions

**Status:** RATIFIED — Product Owner, 2026-10-30 (chat, questions put one batch at a time with the architect's
recommendation first; the PO's exact chosen labels): Q-1 "Kayan pencere + kesme (Önerilen)" (sliding window plus abort),
Q-2 "443, host adıyla (Önerilen)" (443 by host name), Q-3 "%75 ham kapalı, %85 redakte kapalı (Önerilen)" (75 % raw off,
85 % redacted off), Q-4 "Metadata + karar + redakte içerik (Önerilen)" (metadata, verdict and redacted content), Q-5
"Önerilen paket (Önerilen)" (the recommended package), Q-6 "Kişisel blok + yönetilen cihaz (Önerilen)" (personal use
blocked, managed devices only), Q-9 "LDAP/AD, sonra SAML (Önerilen)" (LDAP/AD, then SAML), Q-10 "Evet (Önerilen)" (yes),
Q-13 "Pilottan önce (Önerilen)" (before the pilot), Q-14 "1-2 hafta açık, sonra kapalı (Önerilen)" (open for one to two
weeks, then closed), Q-15 "Gradle + Maven taşınabilirlik (Önerilen)" (Gradle with Maven portability), Q-16 "jOOQ
(Önerilen)" (jOOQ).

## Context
ROADMAP's MVP preconditions name Q-1 to Q-6, Q-9, Q-10, Q-13, Q-14, Q-15 and Q-16 as decisions needed before MVP work that
depends on them. The design is FROZEN (`PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md`) with the architect's
recommendations as the phase 0 planning assumption. Phase 0 movement 1 (pull request 4) already built the skeleton on the
Q-15 recommendation. No production data was involved.

## Decision
1. **Q-1.** SSE responses: strict inline blocking at REQMOD plus sliding-window RESPMOD inspection with abort; a streamed
   response is aborted, never redacted. Not chosen: buffering whole responses; REQMOD only.
2. **Q-2.** The LLM API gateway is published on 443 under its own host name (`ai-api.<corp-domain>` pattern; the real name
   is runtime configuration). Not chosen: a dedicated TCP port.
3. **Q-3.** Disk watermark breaker: above 75 % used, raw bodies stop persisting; above 85 %, redacted content stops
   persisting; enforcement and metadata continue in every state. Not chosen: other thresholds; no breaker.
4. **Q-4.** MVP capture mode: metadata, verdict and redacted content from day one; raw content only behind its own key and
   an approval record per platform and group, once the notice, the DPO's approval and the disk watermark allow. Not chosen:
   raw content from day one.
5. **Q-5.** Raw-content access is approved by the pair `security_admin` + `privacy_officer`; the DPO is a directory group,
   not a named person; retention: C1, C2, C6 400 days; C3 90 days; C4 30 days; C7 10 years; C10 14 days; C12 scope plus
   400 days (C6 PII digests follow the PC-6 split already in DATA_CLASSES). Not chosen: two `security_admin`s; other
   retention figures.
6. **Q-6.** Personal AI accounts on the corporate network are blocked with a coaching page and the block event is stored
   without content; contractors and BYOD are in scope only on managed devices; unmanaged devices are governed by vendor
   tenant settings only. Not chosen: personal use allowed without capture; contractors out of scope.
7. **Q-9.** The admin UI logs in through LDAP/AD bind with group-to-role binding in the MVP; SAML 2.0 is added before the
   corporate-platform stage, sharing the same group-to-role binding. Not chosen: SAML only; both from day one.
8. **Q-10.** rwsafe's data-plane PriorityClass (1000) sits above neXus's packet-analysis class (−100) and below every other
   neXus class. Not chosen: all of rwsafe below −100.
9. **Q-13.** The neXus ingress change (host-based routing, Traefik's native 404 for unknown hosts, end of bare-IP console
   access) is delivered before the rwsafe pilot, in a quiet window, with operators informed in advance. Delivery still
   needs the PO's separate go for the change itself (AGENTS.md section 8). Not chosen: later with corporate DNS names.
10. **Q-14.** ProxySG REQMOD for the AI category runs fail-open for one to two weeks of the pilot with the coverage alert
    armed, then fail-closed; Secure ICAP is on from day one and plain ICAP never coexists with fail-open (Q-28, council
    Q-E). The switch is a recorded ProxySG change. Not chosen: fail-closed from the start.
11. **Q-15.** Gradle with lockfiles, plus a CI smoke build of a generated `pom.xml` to keep the Maven path open. Not chosen:
    Maven.
12. **Q-16.** Persistence uses jOOQ. Not chosen: Spring Data JDBC.

## Consequences
- Confirms the FROZEN design as written; no frozen document changes text: ICAP spec §4.4 and ADR-005 (Q-1); ADR-003 and
  PORTS §3 (Q-2); CAPACITY §2 and ADR-009 (Q-3, Q-4); RAW_CONTENT_ACCESS and DATA_CLASSES (Q-5); ADR-007 rollout and
  OUT_OF_SCOPE §4 (Q-6); ADR-001 and the k3s PriorityClass manifest (Q-10); ADR-003 (Q-13); ADR-010 and ROADMAP (Q-14);
  ADR-011 (Q-15, Q-16).
- The architect recommendations stop being planning assumptions for these twelve questions; MVP work that depends on them
  may start once its other preconditions hold (ROADMAP MVP: phase 0 fixtures, ProxySG record, the neXus PR, the Secure ICAP
  client certificate, lab tenants).
- The DPO directory group and the `privacy_officer` group names are runtime configuration, never committed (AGENTS.md
  section 4.2).
- Q-13 adds a phase 1 task: draft the neXus ingress PR for the PO's go; nothing touches neXus before it.
- No new residual risk accepted; Q-29 stays open and still blocks the pilot.

## Open items
Q-7, Q-8, Q-11, Q-12, Q-17 to Q-29 and Q-37 stay in `docs/product/OPEN_QUESTIONS.md`.
