SEAT: privacy-compliance
LENS: KVKK (articles 4–12, 16), the sector regulator's information-systems and secrecy-sharing rules, workplace-monitoring proportionality, data classes and retention, pseudonymisation versus anonymisation, raw-content access, notice, DSAR, breach, secondary use, masking for AI agents, Turkish identifiers.

You are one independent seat of the design-freeze council for rwsafe-ai-gateway (an enterprise AI-usage security gateway: enterprise-tenant enforcement, prompt and response visibility under masking and retention limits, guardrails, a governed LLM API gateway, ICAP behind Broadcom ProxySG, an off-net agent path later; Java/Netty data plane and Spring Boot control plane; same single on-prem k3s node as the sibling product neXus, fully isolated; the organisation is in a regulated sector in Türkiye: KVKK and BDDK-style rules in scope). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. The kickoff council (docs/reviews/COUNCIL_2026_10_30_SEAT_*.md) raised P0/P1 items; the architect answered them in docs/reviews/COUNCIL_RESPONSE.md. Your job: find what the DESIGN still gets wrong or leaves unsafe for your lens, so implementation does not start on a flawed design. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, document and section, what is wrong, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict ACCEPT FREEZE / ACCEPT WITH CORRECTIONS / REJECT, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md
- docs/reviews/COUNCIL_2026_10_30_SEAT_FABLE_PRIVACY_COMPLIANCE.md (your predecessor's P0/P1 list)
- docs/reviews/COUNCIL_RESPONSE.md (section 2 and section 5)
- docs/adr/ADR-009-data-model-retention-and-privacy.md
- docs/security/MASKING_AND_PRIVACY.md
- docs/security/DATA_CLASSES_AND_RETENTION.md
- docs/security/RAW_CONTENT_ACCESS.md
- docs/security/PRIVACY_IMPACT_ASSESSMENT.md
- docs/compliance/REGULATORY_MAPPING.md
- docs/i18n/README.md and docs/i18n/tr/*.md
- docs/product/OPEN_QUESTIONS.md (Q-4, Q-5, Q-6, Q-7, Q-29)
- docs/security/SECURITY_REQUIREMENTS.md (section SR-PRIV only)
