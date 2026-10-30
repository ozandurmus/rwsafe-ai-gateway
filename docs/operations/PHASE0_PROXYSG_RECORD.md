# Phase 0 record: ProxySG estate facts

**Status:** LIVE evidence record (ROADMAP phase 0, "ProxySG capability record" and "SSL-interception bypass audit").
Source: the Product Owner's answers in chat on 2026-10-30, as proxy administrator (Q-20, Q-21). Shapes and counts only:
appliance names, addresses and policy text were not recorded. Each row says what it changes in the FROZEN design;
`docs/product/PLATFORM_MATRIX.md` §1 and the ICAP spec §9 point here for the measured values.

## 1. Facts

| # | Fact | Value (2026-10-30) | Evidence |
|---|---|---|---|
| F-1 | Appliances | **three** virtual appliances, SGOS **7.4.15.x SWG Edition**, managed by Management Center **4.1.x**; Reporter **11.0.x** present | PO, console view |
| F-2 | Secure ICAP | can be defined on the appliances but **has never been made to work** in this estate | PO |
| F-3 | Identity format sent to ICAP | `DOMAIN\user` | PO |
| F-4 | SSL interception of the AI category | **partial**; which AI domains or applications are bypassed is not known yet | PO |
| F-5 | Interception exemption for GitHub domains | none | PO |
| F-6 | Interception exemption for Microsoft 365 / Entra sign-in domains | none | PO |
| F-7 | Interception exemption for Google domains | unknown | PO |
| F-8 | Uncategorised domains | intercepted | PO |
| F-9 | UDP 443 (QUIC) from clients | blocked | PO |
| F-10 | Tenant restrictions today | none: no Entra tenant restrictions v2 policy and no tenant header injected by the proxy | PO |
| F-11 | ICAP maximum object size and its error action | not applicable yet: no ICAP service exists for the AI category; set when the rwsafe service is created | PO |

## 2. What the facts change

- **F-1.** The ProxySG evidence in PLATFORM_MATRIX §1 cites 7.3.x knowledge-base articles (WebSocket, HTTP/2); those rows
  stay **UNVERIFIED for 7.4.15.x** until checked against 7.4 release notes. Three appliances mean three ICAP clients: the
  H-1 firewall set `@icap_clients` holds three addresses (runtime configuration, never committed), and capacity planning
  counts three connection pools. Policy is pushed once from Management Center to all three.
- **F-2.** The pilot starts on plain ICAP under exception H-2 (Q-28): at most 30 days, REQMOD fail-closed throughout, and
  the fail-open window only after Secure ICAP works. A Secure ICAP troubleshooting task is added to phase 0 so the
  30-day clock is not spent discovering the cause. On plain ICAP, group claims select no exception (OFF2-12).
- **F-3.** The ICAP identity parser accepts `DOMAIN\user` first; the domain part is treated as a realm label and the user
  part is pseudonymised before persistence (ADR-009). The group header format is still to be confirmed.
- **F-4, F-7.** The AI category is not fully visible today. Phase 0 adds a per-domain check (the vendor domain list in
  `PROXYSG_PHASE0_GUIDE.md` §3) through the appliance's policy trace on one test request per domain; until then every AI
  platform row keeps its "content inspection" column UNVERIFIED for this estate. The ICAP category must be
  intercepted in full before the pilot (SEC-7).
- **F-5, F-6.** GitHub Copilot content and the Microsoft sign-in hosts are visible to the proxy: the Entra headers
  (ADR-007) and Copilot REQMOD inspection are feasible as designed.
- **F-8.** The header-only metadata mode for uncategorised domains (Q-30) is feasible: the traffic is already decrypted.
- **F-9.** Browsers cannot bypass the proxy over HTTP/3; the PLATFORM_MATRIX §1 QUIC row is satisfied for this estate.
- **F-10.** Personal and foreign-tenant sign-ins to Microsoft, Google and ChatGPT are allowed today; phase 1 deploys the
  three headers from scratch on the pilot group (Q-21), after the lab verification of the guide §5.
- **F-11.** The rwsafe ICAP service is created with the object-size limit above rwsafe's 4 MiB REQMOD limit and the
  error action **deny** for the AI category (ADR-010, OFF2-2).

## 3. Still open in phase 0

Which AI domains are bypassed (F-4) and whether Google is exempt (F-7); the cause of the Secure ICAP failure (F-2);
preview size, timeouts and health-check settings are chosen when the rwsafe service is created, not measured; the
masked access-log measurement (`tools/proxysg/access_log_shapes.py`); the Broadcom case (Q-20); lab-tenant header tests
(Q-34).
