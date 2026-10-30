<!-- Argon consultation 2026-10-30T23:28:01Z, model gemini-4-argon-high, effort high; unaltered output except 37 local paths masked (AGENTS.md 4.2) -->

Role: REVIEWER

### (1) EARLIER FINDINGS (D-01 TO D-08 AND N-01 TO N-04)

| Earlier Finding ID | Status | Reason |
|---|---|---|
| D-01 (P0) | CLOSED | Closed together with N-01: [`TextMasker.names`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L886-L951), [`joins`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L1065-L1082), and [`lone`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L1138-L1143) now mask `.`/`_`/`-`-joined pairs in any case, lone non-common given and family names, capitalised (`Case.TITLE` and `Case.UPPER`) names with or without case endings, 3-word lowercase names, mixed-case given+surname pairs, and names before inflected post-titles. |
| D-02 (P0) | CLOSED | [`NameDictionary.match`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/NameDictionary.java#L109-L129) strips simple and compound possessive+case endings, prefers non-`COMMON` then longest stems, restores softened final consonants (`b->p`, `d->t`, `g->k`), and supports 2- and 3-letter stems. |
| D-03 (P0) | CLOSED | [`TextMasker.names`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L886-L1157) handles initials (`Kind.INITIAL`), suffixed first words, canonical sorted run keys for family-name-first forms, hyphenated unlisted capitalised surnames, and `` ` ``, `´`, and `U+02BC` apostrophes. |
| D-04 (P0) | CLOSED | Closed together with N-02: [`TextMasker.digitRuns`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L611-L695), [`parenPhones`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L595-L601), [`ibans`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L519-L571), and [`withoutTokens`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L267-L277) mask all grouped and glued TCKNs, mobile numbers (including `90(5XX)` and space-preserved `(5XX)`), payment cards, IBANs, and 6+ digit runs across all paths while exempting only standalone calendar dates and blanking masker tokens before `SiemRecords` post-checks. |
| D-05 (P1) | CLOSED | Homograph names are in [`common-words.txt`](file://<workspace-root>/java/control/src/main/resources/io/rwsafe/control/privacy/names/common-words.txt#L1-L211) and lowercase everyday words alone stay unmasked, while given+surname pairs across cases join under the privacy-first rule in [`TextMasker.joins`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L1080-L1081). |
| D-06 (P1) | CLOSED | Closed together with N-03: unified layer ordering in [`TextMasker.run`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L175-L202), separator-normalised estate matching in [`estate`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L734-L799), URL userinfo masking in [`urlHosts`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L428-L462), Turkish dotless-`ı` folding in [`perChar`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L322-L329), and shared [`IdentifierCheck`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/IdentifierCheck.java#L55-L79) delegation in [`SiemRecords`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/siem/SiemRecords.java#L191-L236). |
| D-07 (P1) | CLOSED | [`PrivacyKeys.maskingAvailable`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/PrivacyKeys.java#L67-L69) requires `!estateTerms.isEmpty()`, failing closed with HTTP 503 on an empty or comment-only estate dictionary file. |
| D-08 (P1) | CLOSED | [`TextMasker.RULE_SET`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L42) is `rwmask-v1-slice2`, Layer 5 keyword-following tokens, user-directory paths, and serial-like tokens are implemented, [`Pseudonymiser.word`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/Pseudonymiser.java#L109-L130) has a deterministic 8-consonant fallback, and [`TextMasker.detectors`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L296-L351) withholds the entire string on `overLimit()`. |
| N-01 (P0) | CLOSED | [`TextMasker.lone`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L1138-L1143) accepts `titled \|\| w.capitalised()`; [`names`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L889-L909) computes `titledAhead` and `plainName`; [`joins`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L1065-L1082) joins mixed-case given+surname pairs where at least one is non-common and restricts post-initial joins; [`NameDictionary.inflectionOf`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/NameDictionary.java#L135-L146) recognises inflected post-titles; [`word`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L1004-L1007) treats single letters glued by `._-` in any case as `Kind.INITIAL`. |
| N-02 (P0) | CLOSED | [`TextMasker.dateLength`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L676-L681) rejects date prefixes/suffixes joined by `DIGIT_JOINS` to digits; [`PAREN_PHONE`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L71-L72) includes `90` and binds the trailing separator inside the optional prefix group; [`TextMasker.withoutTokens`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L267-L277) blanks masker tokens before [`SiemRecords.ledgerReason`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/siem/SiemRecords.java#L213-L215) checks for remaining identifier shapes. |
| N-03 (P1) | CLOSED | [`TextMasker.foldTerm`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L781-L799) and [`estate`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L741-L759) collapse all separator and whitespace runs to `'-'`; [`urlHosts`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L443-L451) runs before `emails` and masks URL userinfo (`USR-` and `[REDACTED:SECRET]`); [`perChar`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L322-L329) folds via `foldChar`. |
| N-04 (P1) | CLOSED | [`TextMasker.STOP_WORDS`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L98-L114) covers ordinary English and Turkish operational words (including `"This is captured user content"`) and [`keywords`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/TextMasker.java#L1285-L1288) requires a digit in words following `TCKN_WORDS` and `IBAN_WORDS`. |

---

### (2) DISSENT (NEW FINDINGS)

| Finding ID | File and line or symbol | What is wrong | Severity | Concrete correction |
|---|---|---|---|---|
| None | — | No new P0, P1, or P2 findings. | — | — |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| **Q-1 (tracked as Q-44):** Class tokens (`TCKN-`, `TEL-`, `HST-`, `CARD-`, `NUM-`, `EST-`, `IBAN-`, `CUST-`, `SER-`) use `<4 hex>` (16 bits) per frozen [`MASKING_AND_PRIVACY.md`](file://<workspace-root>/docs/security/MASKING_AND_PRIVACY.md#L76-L78) while the B3 `pseudonym_registry` is deferred to a later slice. Should `<4 hex>` class tokens be widened to `<8 hex>` via a PO decision record before production rollout? | Ratify widening class tokens to `<8 hex>` via a PO decision record before production rollout so read-side pseudonyms remain collision-resistant without synchronous database writes. |

---

### (4) VERDICT

MERGE

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

```text
/plan REVIEW: second confirmation review of pull request 26 after corrections (AGENTS.md section 9, security-sensitive: the masking funnel),
branch `feature/masking-layers-4-5`
LENS: whether the corrections for the still-open D-01 (P0), D-04 (P0) and D-06 and the new N-01 to N-04 close each finding without opening a new escape or false positive, and whether masking layer 4 (Turkish names) and layer 5 (free-text heuristics), rule set `rwmask-v1-slice2`, hold against
AGENTS.md section 4 (4.8 to 4.12), docs/architecture/MASKING_AND_PRIVACY.md (FROZEN) and the SR-PRIV requirements.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway whose masked role must
never see a real identifier, with Turkish identifiers first class; a public repository). You start from a fresh context.
Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or
widen the review. Your job: find any Turkish name form (case endings with or without apostrophe, capitals, dotted and
dotless i, NFD, family name first, initials, hyphenated or double surnames) that escapes; any glued or grouped number,
account, IBAN, host or address shape that escapes; any false positive that would mask ordinary Turkish words or product
terms; any pseudonym that is unstable, reversible, collides silently or differs between screens, exports and SIEM; any
backtracking regex or super-linear scan; any path where a missing dictionary or key serves unmasked text instead of 503;
and any deviation from the frozen masking design. For each earlier finding say CLOSED or OPEN with the reason. Return exactly: (1) a table (earlier finding id, CLOSED or OPEN, reason), (2) a DISSENT table for new findings
(finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE
PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then
(5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (section 4)
- docs/architecture/MASKING_AND_PRIVACY.md
- docs/reviews/PR26_2026_10_31_ARGON_MASKING_LAYERS_4_5.md (the earlier findings)
- docs/reviews/PR26_2026_10_31_ARGON_MASKING_LAYERS_4_5_RECHECK.md (the first confirmation findings)
- docs/reviews/PR26_2026_10_31_RESPONSE.md
- every file under java/control/src/main/java/io/rwsafe/control/privacy/
- java/control/src/main/resources/io/rwsafe/control/privacy/names/ (README and the lists)
- java/control/src/main/java/io/rwsafe/control/siem/SiemRecords.java
- java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java
- every test under java/control/src/test/java/ that names "Masker", "Masking", "Name", "Pseudonym" or "IdentifierCheck"
```
