# GitHub repository settings (as they stand; the PO owns them)

Repository: public, created by the PO on 2026-10-30 (`docs/design/PO_DECISION_RECORD_2026_10_30_GIT_AUTHORITY_AND_PUBLIC_REPOSITORY.md`).

Description: Enterprise AI-usage security gateway: tenant enforcement, prompt/response visibility with masking,
guardrails, governed LLM API gateway. Java 21, Spring Boot, Netty, React/TypeScript, Kubernetes, beside neXus.

Topics: ai-security, dlp, icap, proxy, llm-gateway, java, spring-boot, netty, react, typescript, kubernetes, privacy, kvkk.

Branch protection on `main` (verified 2026-10-30 through the API): pull request required; **zero** approving reviews
(the repository has one human account, so an approval is not available; the second review on security-sensitive paths is
recorded in the pull request as a review-script or code-review run, AGENTS.md section 9); stale reviews dismissed; no
force push; no deletion; administrators exempt for emergency repair by the PO only. To add once the validation workflow
exists: required status check (privacy gate, unit tests). A `CODEOWNERS` file names the security-sensitive paths
(`java/dataplane/**`, `java/detect/**`, `java/control/**/privacy/**`, `policy/**`, `deploy/**`, `tools/privacy/**`) so the
recorded second review is visible per PR. Q-37 tracks the return to GitHub approvals.

Agent permissions: `.claude/settings.json` (committed) carries the allow rules for push, PR, merge, the review scripts and
the privacy gate, the deny rules for force push, deletion and visibility changes, and the standing-authorisation
statement for the harness.

Secrets: none in GitHub Actions; CI runs the gate and unit tests only; everything that touches HOST-A runs from the
operator's machine.
