REVIEW: second independent review of pull request 37 (AGENTS.md section 9, security-sensitive: the image build path),
branch `feature/pilot-gradle-dist`
LENS: whether letting the image build use a locally placed Gradle distribution keeps the build pinned and verified and
keeps the runtime image unchanged.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any way an unpinned or tampered Gradle
distribution is accepted (the wrapper's distributionSha256Sum, validateDistributionUrl), any shell or sed injection
through a file name, any trace of the distribution or its path in the runtime image, and any step that is not reversible.
Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is
wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation),
(4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received,
verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8)
- deploy/images/dataplane.Containerfile, deploy/images/control.Containerfile
- java/gradle/wrapper/gradle-wrapper.properties
- docs/operations/PILOT_RUNBOOK.md (sections 4, 4b)
- .gitignore
