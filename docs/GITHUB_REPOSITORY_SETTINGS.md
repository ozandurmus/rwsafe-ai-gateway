# Proposed GitHub repository settings (for the PO, who creates the repository)

Description: Enterprise AI-usage security gateway: tenant enforcement, prompt/response visibility with masking,
guardrails, governed LLM API gateway. Java 21, Spring Boot, Netty, React/TypeScript, Kubernetes, beside neXus.

Topics: ai-security, dlp, icap, proxy, llm-gateway, java, spring-boot, netty, react, typescript, kubernetes, privacy, kvkk.

Branch protection on `main`: require a pull request, require the validation workflow (privacy gate, unit tests), require
one approving review, dismiss stale approvals, no force push, no deletion; the orchestrator merges. A `CODEOWNERS` file
names the second-reviewer requirement for security-sensitive paths (`java/dataplane/**`, `java/detect/**`,
`java/control/**/privacy/**`, `policy/**`, `deploy/**`, `tools/privacy/**`).

Secrets: none in GitHub Actions; CI runs the gate and unit tests only; everything that touches HOST-A runs from the
operator's machine.
