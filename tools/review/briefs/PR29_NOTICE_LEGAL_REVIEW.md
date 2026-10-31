REVIEW: second independent review of pull request 29 (AGENTS.md section 9, security-sensitive: deploy manifests and the
end-user notice that gates content capture), branch `feature/notice-legal-review`
LENS: whether the end-user catalogue, its rendering, the notice version gate and the deploy contract still hold after the
PO's legal-review decisions in docs/design/PO_DECISION_RECORD_2026_10_31_END_USER_NOTICE_LEGAL_REVIEW.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway that shows employees a
Turkish notice; a public repository). You start from a fresh context. Read AGENTS.md and ONLY the files listed below,
with the Read tool, inside this repository. Do not edit, run shell, or widen the review. Your job: find any text that
still promises something the product does not do (a full-text tier, an objection-based opt-out), any text that differs
from the decision record, any leftover placeholder or configuration for the removed retention value that could make the
notice incomplete (and so keep the capture gate closed) or render a blank, any review copy that no longer mirrors the
catalogue, and any deploy or contract change that breaks the manifest rules. Return exactly: (1) a CONSENT table (area,
verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete
correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE
WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never
quote or invent an address, host name, account, serial or secret; the repository holds none and neither should your
output. English only, except quoted Turkish catalogue text.

Files to read, in this order:
- AGENTS.md (sections 3, 4)
- docs/design/PO_DECISION_RECORD_2026_10_31_END_USER_NOTICE_LEGAL_REVIEW.md
- java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties
- docs/i18n/README.md and every file under docs/i18n/tr/
- every file under java/platform-core/src/main/java/ that names "EndUser"
- deploy/rwsafe/base/30-dataplane.yaml, deploy/rwsafe/base/40-control.yaml, deploy/rwsafe/contracts/runtime-contracts.json
- java/platform-core/src/test/java/io/rwsafe/platform/enduser/ (all tests)
