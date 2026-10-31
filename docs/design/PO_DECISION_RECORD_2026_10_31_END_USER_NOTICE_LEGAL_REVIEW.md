# PO decision record 2026-10-31: legal review of the end-user notice texts (LR-1 to LR-7)

**Status:** RATIFIED — Product Owner, 2026-10-31 (chat, answering the seven LEGAL-REVIEW items of the end-user
catalogue one at a time, relayed by the orchestrating session). The PO's answers, verbatim, with an English gloss:

| Id | Key | PO answer (verbatim) | English gloss |
|---|---|---|---|
| LR-1 | `notice.raw.text` | "Şimdilik metinden çıkar (Önerilen)" | "Remove it from the text for now (recommended)" |
| LR-2 | `notice.basis.text` | "Olduğu gibi kalsın (Önerilen)" | "Keep it as is (recommended)"; the full-text tier is dropped from it as a consequence of LR-1 |
| LR-3 | `notice.transfer.text` | "Olduğu gibi kalsın (Önerilen)" | "Keep it as is (recommended)" |
| LR-4 | `notice.retention.text` | "Olduğu gibi kalsın (Önerilen)" | "Keep it as is (recommended)"; the full-text clause is dropped from it as a consequence of LR-1 |
| LR-5 | `notice.rights.text` | "Bu cümleyi metinden çıkaralım" | "Let us remove this sentence from the text" (the objection sentence) |
| LR-6 | `block.class.noexception` | "Olduğu gibi kalsın (Önerilen)" | "Keep it as is (recommended)" |
| LR-7 | `notice.acknowledge.text` | "Olduğu gibi kalsın (Önerilen)" | "Keep it as is (recommended)" |

## Context
Pull request 22 added the Turkish end-user catalogue (first-use notice, block, coaching and stream-termination texts;
`java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties`, review copies under
`docs/i18n/tr`). Seven wording items were marked `LEGAL-REVIEW LR-1` to `LR-7` for the Product Owner and the data
protection officer. The second review of PR 22 (`docs/reviews/PR22_2026_10_31_ARGON_END_USER_NOTICES.md`, answered in
`docs/reviews/PR22_2026_10_31_RESPONSE.md`) corrected the wording (D-01 to D-08, PO-Q1 to PO-Q3 taken as recommended)
and left the LR markers open; the catalogue stood at `tr-2`. The notice described a full-text capture tier (content
with detected secrets and personal data removed, AGENTS.md 4.13) that the product does not build, and a rights sentence
promising that content is not stored after an objection.

## Decision
1. `notice.raw.text` and its paragraph in the notice's data section are removed; the full-text tier returns, with a new
   catalogue version, only if it is ever built (LR-1).
2. `notice.basis.text` keeps the basis split (art. 5/2-ç for usage records and security decisions, art. 5/2-f for masked
   content) and the sentence that explicit consent is not a basis, without the full-text tier (LR-2). New text:
   "Kullanım kayıtları ve güvenlik kararları, kurumun bilgi sistemleri güvenliğine ilişkin hukuki yükümlülüğü nedeniyle
   (Kanun'un 5. maddesinin 2. fıkrasının (ç) bendi); maskelenmiş içerik, kurumun meşru menfaati nedeniyle (Kanun'un 5.
   maddesinin 2. fıkrasının (f) bendi) işlenir. Bu işleme açık rızanıza dayanmaz; bu nedenle sizden rıza istenmez."
3. `notice.transfer.text` is kept as is (LR-3).
4. `notice.retention.text` keeps the figures (Q-5: 400 days metadata, 90 days masked content) and the deletion sentence,
   without the full-text clause (LR-4). New text: "Kullanım kayıtları ve güvenlik kararları {{retention_metadata}} gün,
   maskelenmiş içerik {{retention_redacted}} gün saklanır. Süresi dolan bilgiler silinir ve silme işlemi kayıt altına
   alınır."
5. `notice.rights.text` loses the objection sentence (LR-5). New text: "Kanun'un 11. maddesindeki haklarınız için
   (bilgilerinize erişmek, düzeltilmesini ya da silinmesini istemek, itiraz etmek gibi) {{dpo_contact}} adresine
   başvurabilirsiniz." Not chosen: keeping the sentence.
6. `block.class.noexception` is kept as is (LR-6).
7. `notice.acknowledge.text` is kept as is (LR-7).
8. The catalogue moves to `tr-3`.

## Consequences
- Catalogue `tr-3` is a new notice version (PC-1): every employee acknowledges again.
- The full-text capture tier and an objection-based capture opt-out are not offered to employees; the notice promises
  neither.
- The `retention_raw` placeholder is removed from the configuration: `EndUserCatalogue.CONFIGURED` and its key map,
  `EndUserPages`' notice sections, `RWSAFE_ENDUSER_RETENTION_RAW` in `deploy/rwsafe/base/30-dataplane.yaml` and
  `deploy/rwsafe/base/40-control.yaml`, the `rwsafe-enduser` contract in `deploy/rwsafe/contracts/runtime-contracts.json`
  (five keys), `docs/i18n/README.md`, the runbook and every test. An existing `retention-raw` key in a deployed
  ConfigMap is no longer read.
- Every `LEGAL-REVIEW LR-n` marker is removed from the catalogue and the review copies; `docs/i18n/README.md` records the
  decisions in its "Legal review" section; `EndUserCatalogueTest` and `EndUserCatalogueDocsTest` assert that no marker
  remains and that no text names the full-text tier.
- AMENDS `docs/reviews/PR22_2026_10_31_RESPONSE.md` where it says the LR markers stay open.

## Open items
- The data protection officer's confirmation of the approved texts is the Product Owner's responsibility; it is not
  tracked in the repository.
