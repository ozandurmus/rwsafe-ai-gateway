# End-user texts (Turkish)

The one place in the repository where content is Turkish by design: KVKK article 10 notice validity requires that the
people being informed read it in their language (AGENTS.md section 3). Keys, file names and comments are English.

The product renders these texts from its catalogue
`java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties` (`EndUserCatalogue`,
`EndUserPages`). The files under `tr/` are the review copies for the Product Owner, the data protection officer and legal:
each heading is a catalogue key and `EndUserCatalogueDocsTest` fails when a copy and the catalogue differ. Change both
together and bump `catalogue.version` (currently `tr-3`) with every text change.

| File | Where it is shown |
|---|---|
| `tr/notice_first_use.md` | first use of an AI platform through the gateway (web banner, IDE first-run notification) |
| `tr/block_page.md` | the 403 block page per reason kind, its footer, and the API error message |
| `tr/personal_account_block.md` | the login-step block for a personal (non-corporate) account (Q-6) |
| `tr/coaching_warn.md` | the coaching page shown after a WARN verdict (out of band) |
| `tr/stream_terminated.md` | the message delivered when a streamed response is aborted |
| `tr/labels.md` | the class and reason labels inserted into the texts above |
| `tr/exception_request.md` | draft justification form text (English title, Turkish body); not in the product catalogue yet, never offered for fail-closed classes (PC-5) |

## Placeholders

Configured at runtime from the environment (`RWSAFE_ENDUSER_<NAME>`, an uncommitted ConfigMap; never a literal in the
repository): `{{controller_name}}` (the data controller's legal name), `{{dpo_contact}}`, `{{policy_link}}` (rendered
as text, never as a link), `{{retention_metadata}}`, `{{retention_redacted}}` (whole days). A value
that is too long, holds a control character or a placeholder, or (for a retention figure) is not a number is ignored.

Filled by the product: `{{class}}` and `{{reason}}` (a label from `tr/labels.md`, never the value), `{{platform}}` (the
platform id), `{{ref}}` (the correlation id the employee can quote; letters, digits and `-` only), `{{notice_version}}`.

Every text and every value is HTML-escaped; a page has an inline style, a Content-Security-Policy that loads nothing,
and no script, link or external resource.

## Notice version and acknowledgement (PC-1, C12)

The notice version is `catalogue.version` plus the first 8 hex digits of SHA-256 over the rendered notice without its
own version (for example `tr-3-0a1b2c3d`), so a change to a text or to a configured value is a new version and every
user acknowledges again. While a configured value is missing the notice has no version, is not shown, and nothing can
be acknowledged: content capture stays off for everyone (SR-PRIV-10). The control plane records the time it first
issues a version (`notice_version`); an acknowledgement names an issued version only.

An acknowledgement (C12) records the user's pseudonym, the notice version, the date and the source (`banner`,
`ide_first_run`, `directory_attribute` for the HR record imported from the directory with its version and date (Q-35),
`gateway_credential_issue`). It is proof that the duty to inform was met, never approval or consent (Q-32). The
interactive sources (banner, IDE first run, credential issue) record the current version only; the directory may also
carry an earlier issued version, which is kept as history and does not open content capture. The date is never before
the version's issue time (5 minutes of clock skew allowed) nor more than 5 minutes in the future.

## Legal review

The Product Owner approved these texts on 2026-10-31
(`docs/design/PO_DECISION_RECORD_2026_10_31_END_USER_NOTICE_LEGAL_REVIEW.md`); the catalogue moved to `tr-3`, so every
employee acknowledges again (PC-1). Obtaining the data protection officer's confirmation is the Product Owner's
responsibility.

- LR-1 `notice.raw.text`: removed. The full-text tier is not built; its text returns with a new catalogue version only
  if the tier is ever built.
- LR-2 `notice.basis.text`: the basis split (art. 5/2-ç for usage records and security decisions, 5/2-f for masked
  content) and the sentence that explicit consent is not a basis stay; the full-text tier is dropped from it.
- LR-3 `notice.transfer.text`: kept as is.
- LR-4 `notice.retention.text`: the figures (Q-5: 400 days metadata, 90 days masked content) and the deletion sentence
  stay; the full-text clause and the `{{retention_raw}}` placeholder are removed.
- LR-5 `notice.rights.text`: the objection sentence is removed; capture opt-out on objection is not offered.
- LR-6 `block.class.noexception`: kept as is.
- LR-7 `notice.acknowledge.text`: kept as is.
