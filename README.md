# rwsafe-ai-gateway

Security gateway for how employees use AI assistants and coding agents: enterprise-tenant enforcement, prompt and response
visibility under masking and retention limits, guardrails (allow, warn, redact, block), a governed LLM API gateway, and
neXus-grade administration (LDAP/AD, RBAC, trigger-enforced audit, syslog/SIEM, SNMP, CLI parity, a masked role for AI
agents, health). First product of the **rwsafe** family; runs beside neXus on the same k3s node in its own namespace.

**Phase:** implementation, phase 0 (discovery and measurement; no production change). The design is **FROZEN** by
`docs/design/PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md` (2026-10-30) and ADR-001 to ADR-011 are ACCEPTED; product
code starts with the phase 0 repository skeleton (`docs/product/ROADMAP.md`).

## Start here

| Reader | Read |
|---|---|
| Any agent or engineer | `AGENTS.md` (constitution), then `roles/<ROLE>.md` |
| Product Owner | `docs/product/OPEN_QUESTIONS.md`, `docs/design/PO_DECISION_RECORD_*.md`, `docs/reviews/COUNCIL_RESPONSE.md`, `docs/product/ROADMAP.md` |
| Architecture | `docs/architecture/ARCHITECTURE.md`, `docs/adr/`, `docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md` |
| Platform and operations | `docs/operations/` (ports, capacity, hardening, deploy runbook), `deploy/rwsafe/` |
| Security and privacy | `docs/security/`, `docs/compliance/REGULATORY_MAPPING.md` |
| Product | `docs/product/` (platform matrix, out of scope, competitive reference) |
| Kickoff inputs (frozen) | `kickoff/` |

## Rules in one breath

English repository, Turkish chat with the PO. No real host name, address, account, serial, domain or e-mail anywhere; no
prompt body to any agent or reviewer; HOST-A read-only and masked; every change through a pull request; the privacy gate
(`tools/privacy/repository_privacy_check.py`) runs before every commit.
