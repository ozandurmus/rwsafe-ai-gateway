# PO decision record 2026-10-30: the remaining open questions

**Status:** RATIFIED — Product Owner, 2026-10-30 (chat, questions put in batches with the architect's recommendation
first; the PO's exact chosen labels or words): Q-7 "Sınıflı başlangıç (Önerilen)" (class-based start), Q-8 "Evet, telafi
kontrolleriyle (Önerilen)" (yes, with compensating controls), Q-11 "Şimdilik raporla (Önerilen)" (report for now), Q-18
"Talep görülürse evet (Önerilen)" (yes if demand is shown), Q-19 "MVP sonrası, önce tarayıcı (Önerilen)" (after the MVP,
browser first), Q-22 "MVP'de yalnızca asenkron (Önerilen)" (asynchronous only in the MVP), Q-24 "İlk frontend commit'inde
karar, Axios kabul (Önerilen)" (decide at the first frontend commit, Axios acceptable), Q-26 "cosign, anahtar Secret'ta
(Önerilen)" (cosign, key in a Secret), Q-27 "161→1161 yönlendirme" (161→1161 redirect), Q-28 "Düz ICAP en fazla 30 gün"
(plain ICAP for at most 30 days) and, after the architect's one objection that this conflicted with the Q-14 record,
"Düz ICAP + fail-closed (Önerilen)" (plain ICAP with fail-closed), Q-29 "Pilot için imzala (Önerilen)" (sign for the
pilot), Q-37 "Kurumsal GitHub'a geçişte (Önerilen)" (at the move to the corporate GitHub), Q-12 "Şimdilik HOST-A yeterli"
(HOST-A is enough for now), Q-20 and Q-21 "proxy admin benim ben göndereceğim. ne gerekiyorsa guidedan beni
yönlendirirsin ben yaparım" (I am the proxy admin, I will send it; guide me through whatever is needed and I will do it),
Q-17, Q-23, Q-25 "Varsayımla ilerle, ihtiyaçta ver (Önerilen)" (proceed on the assumption, supply when needed).

## Context
After the MVP-blocking questions (`PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`), eighteen questions stayed
open in `docs/product/OPEN_QUESTIONS.md`. The design is FROZEN; this record amends frozen text only where Q-27 and Q-28
depart from the recommendation. No production data was involved.

## Decision
1. **Q-7.** Model and region allowlist starts class-based: public data to every enterprise tenant; internal data to
   enterprise tenants with a DPA; customer data, banking secret and special-category data to no external model until a
   documented contract and the regulator reading in REGULATORY_MAPPING allow it. Not chosen: a looser start.
2. **Q-8.** Cloud-side agents are out of gateway scope and governed by tenant settings with the compensating controls in
   OUT_OF_SCOPE §1. Not chosen: blocking their consoles.
3. **Q-11.** neXus's node over-commit is reported, not changed; rwsafe protects neXus by being evicted first. Not chosen:
   a neXus change now.
4. **Q-12.** No off-host backup target for now; rwsafe's encrypted backups stay on HOST-A inside the platform set. Not
   chosen: naming a target in Türkiye before the pilot. Consequence: a host loss loses the backups too; this is added to
   the Q-29 residual risks below.
5. **Q-17, Q-23, Q-25.** Proceed on the working assumptions: names compatible with GitHub and k3s with deviations recorded
   (Q-17); the PO supplies customer-number format rules (regex shapes, no samples) before the detector library and names
   come from a public list (Q-23); the XDR product is named when the agent phase starts (Q-25). The three stay open as
   information requests.
6. **Q-18.** A chained forward proxy (3128) is built after phase 0 only if measured demand for a sanctioned WebSocket flow
   is shown, through its own ADR. Not chosen: never.
7. **Q-19.** The endpoint agent comes after the MVP, browser extension (MV3) first, sized by a feasibility spike; the
   IDE/CLI agent follows if the trust matrix shows off-net CLI use is common. Not chosen: IDE/CLI first; both together.
8. **Q-20, Q-21.** The PO is the proxy administrator and performs the ProxySG and Broadcom steps; the architect or
   engineer session prepares step-by-step guidance and masked request texts. The Broadcom case (Cloud SWG forwarding the
   AI category to on-prem ICAP) is opened in phase 0; the Entra, Google and ChatGPT tenant headers go on the pilot group's
   policy layer in phase 1, and the Entra tenant restrictions v2 status is checked by the PO in phase 0.
9. **Q-22.** The ML prompt-injection tier is asynchronous only in the MVP. Not chosen: inline after measurement (may be
   revisited by a new record).
10. **Q-24.** The frontend HTTP client is decided at the first frontend commit; Axios is acceptable.
11. **Q-26.** Images are signed with cosign, the key held in a Kubernetes Secret, verified at deploy. Not chosen: a
    corporate signing service.
12. **Q-27.** SNMP is reached on the standard port 161 through a host firewall redirect to 1161 (exception H-3 approved as
    a redirect, source restricted to the NMS pollers). Not chosen (architect's recommendation): polling 1161 directly.
13. **Q-28.** The pilot may start on plain ICAP (1344) for at most 30 days while the Secure ICAP client certificate is
    issued (exception H-2 approved). During plain ICAP, REQMOD runs **fail-closed**; the one-to-two-week fail-open window
    of Q-14 starts only after Secure ICAP is on. Plain ICAP and REQMOD fail-open never run together (council Q-E kept).
    Not chosen: Secure ICAP from day one (the recommendation); plain ICAP with fail-open.
14. **Q-29.** The residual risks listed in THREAT_MODEL §10 and Q-29 are accepted for the pilot and reviewed before
    production: no HSM (host root and cluster admin can read Secrets and PVCs); streamed responses can be aborted, not
    redacted; pinned apps and off-net users invisible until the agent phase; MV3 blocking best-effort; an AI agent as
    `replay_viewer` on production data receives pseudonymised personal data abroad; low-entropy PII digests reversible
    if the digest key leaks; redaction leaves undetected names and context in C3; **plus** backups on the same host
    (Q-12) and, for up to 30 days, unencrypted ICAP between ProxySG and rwsafe with identity claims not bound to a client
    certificate (Q-28; group claims select no exception on plain connections, OFF2-12). Until production review, AI agents
    see aggregates only on production data unless a later record says otherwise.
15. **Q-37.** GitHub approvals return when the product moves to the corporate GitHub Enterprise instance after the
    skeleton stage; zero approvals with recorded second reviews stays the accepted residual risk until then (review
    2027-01-31).

## Consequences
- AMENDS (FROZEN documents, by this record): `docs/operations/HARDENING_EXCEPTIONS.md` H-2 and H-3 and the nftables
  snippet; `docs/product/ROADMAP.md` MVP preconditions and phase 1 pilot row; `docs/adr/ADR-010-fail-open-and-fail-closed.md`
  pilot-order paragraph; `docs/operations/PORTS_AND_RESOURCES.md` SNMP row.
- AMENDS `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md` item 10 ("Secure ICAP is on from day one"): read it as
  "Secure ICAP, or plain ICAP under H-2 with REQMOD fail-closed".
- Policy registry seed (MVP): the class × platform × region allowlist of item 1, with fail-closed rows for customer data,
  banking secret and special-category data.
- Phase 0 tasks: a ProxySG and Broadcom guide for the PO (Q-20, Q-21), masked, with the PO executing every step.
- Q-29 signed for the pilot; the pilot is no longer blocked by it. Review before production.

## Open items
Q-17, Q-23 and Q-25 stay in `docs/product/OPEN_QUESTIONS.md` as information requests. Every other question is decided.
