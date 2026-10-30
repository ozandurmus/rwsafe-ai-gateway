REVIEW: second independent review of pull request 26 (AGENTS.md section 9, security-sensitive: the masking funnel),
branch `feature/masking-layers-4-5`
LENS: whether masking layer 4 (Turkish names) and layer 5 (free-text heuristics), rule set `rwmask-v1`, hold against
AGENTS.md section 4 (4.8 to 4.12), docs/architecture/MASKING_AND_PRIVACY.md (FROZEN) and the SR-PRIV requirements.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway whose masked role must
never see a real identifier, with Turkish identifiers first class; a public repository). You start from a fresh context.
Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or
widen the review. Your job: find any Turkish name form (case endings with or without apostrophe, capitals, dotted and
dotless i, NFD, family name first, initials, hyphenated or double surnames) that escapes; any glued or grouped number,
account, IBAN, host or address shape that escapes; any false positive that would mask ordinary Turkish words or product
terms; any pseudonym that is unstable, reversible, collides silently or differs between screens, exports and SIEM; any
backtracking regex or super-linear scan; any path where a missing dictionary or key serves unmasked text instead of 503;
and any deviation from the frozen masking design. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table
(finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE
PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then
(5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (section 4)
- docs/architecture/MASKING_AND_PRIVACY.md
- every file under java/control/src/main/java/io/rwsafe/control/privacy/
- java/control/src/main/resources/io/rwsafe/control/privacy/names/ (README and the lists)
- java/control/src/main/java/io/rwsafe/control/siem/SiemRecords.java
- java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java
- every test under java/control/src/test/java/ that names "Masker", "Masking", "Name", "Pseudonym" or "IdentifierCheck"
