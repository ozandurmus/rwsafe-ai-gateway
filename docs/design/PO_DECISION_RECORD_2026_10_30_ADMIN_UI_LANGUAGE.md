# PO decision record 2026-10-30: admin UI language

**Status:** RATIFIED — Product Owner, 2026-10-30 (chat, question with the recommendation first): "TR/EN seçmeli,
varsayılan Türkçe (Önerilen)" (selectable TR/EN, Turkish by default).

## Context
AGENTS.md section 3 makes end-user notices Turkish (KVKK article 10) and every repository artifact English, but did not
decide the language of the admin UI. Pull request 12 shipped the admin UI with English labels. The PO reviewed a Turkish
mockup of the full screen set (design canvas "rwsafe Yönetim Arayüzü") and was asked to choose: Turkish only, English only,
or selectable. No production data was involved.

## Decision
1. The admin UI is bilingual: Turkish and English, selectable per user, **Turkish by default**.
2. Every UI string lives in one message catalogue per language (keys in English, the code stays English); no string is
   hard-coded in a component.
3. Server reason codes stay stable English identifiers; the UI maps them to the selected language, so logs, the CLI and
   the SIEM keep one vocabulary.
4. The CLI stays English.

Not chosen: Turkish only; English only.

## Consequences
- AMENDS AGENTS.md section 3 by interpretation: the admin UI's message catalogues (`tr`, `en`) are product i18n
  resources, like the end-user texts; their keys and surrounding code stay English.
- Frontend: an i18n layer, a language switch in the user menu remembered per user, Turkish formats for numbers and dates
  in Turkish (`tr-TR`), tests that fail when a key is missing in either catalogue.
- The design canvas is the reference for the Turkish wording of the existing screens.

## Open items
None.
