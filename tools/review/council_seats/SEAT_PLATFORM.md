SEAT: platform-architecture
LENS: isolation on the shared k3s node with neXus (quota, priority, eviction, disk, network), inline ICAP performance and availability with ProxySG, the Netty data plane and its limits, zero-downtime rollout on one node, capacity sum against the measured host, observability, portability to OpenShift, the shared delivery tooling and build contention, the exact neXus ingress change.

You are one independent seat of the design-freeze council for rwsafe-ai-gateway (an enterprise AI-usage security gateway: enterprise-tenant enforcement, prompt and response visibility under masking and retention limits, guardrails, a governed LLM API gateway, ICAP behind Broadcom ProxySG, an off-net agent path later; Java/Netty data plane and Spring Boot control plane; same single on-prem k3s node as the sibling product neXus, fully isolated; the organisation is in a regulated sector in Türkiye: KVKK and BDDK-style rules in scope). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. The kickoff council (docs/reviews/COUNCIL_2026_10_30_SEAT_*.md) raised P0/P1 items; the architect answered them in docs/reviews/COUNCIL_RESPONSE.md. Your job: find what the DESIGN still gets wrong or leaves unsafe for your lens, so implementation does not start on a flawed design. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, document and section, what is wrong, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict ACCEPT FREEZE / ACCEPT WITH CORRECTIONS / REJECT, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md
- docs/reviews/COUNCIL_2026_10_30_SEAT_ARGON_PLATFORM.md (your predecessor's P0/P1 list)
- docs/reviews/COUNCIL_RESPONSE.md (section 1 and section 5)
- docs/architecture/ARCHITECTURE.md
- docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md
- docs/adr/ADR-001-hosting-and-namespace-isolation.md
- docs/adr/ADR-002-separate-database-instance.md
- docs/adr/ADR-003-reverse-proxy-and-host-based-routing.md
- docs/adr/ADR-010-fail-open-and-fail-closed.md
- docs/adr/ADR-011-shared-tooling-with-nexus.md
- docs/operations/PORTS_AND_RESOURCES.md
- docs/operations/CAPACITY_AND_SLO_MODEL.md
- docs/operations/HARDENING_EXCEPTIONS.md
- docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md
- docs/design/SHIP_PIPELINE_PLAN.md
- deploy/rwsafe/README.md and deploy/rwsafe/overlays/k3s/*.yaml
- docs/reference/CORPORATE_TECHNOLOGY_STACK.md
