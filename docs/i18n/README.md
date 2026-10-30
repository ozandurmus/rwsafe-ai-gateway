# End-user texts (Turkish)

The one place in the repository where content is Turkish by design: KVKK article 10 notice validity requires that the
people being informed read it in their language (AGENTS.md section 3). Keys, file names and comments are English.

The product renders these texts from its catalogue
`java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties` (`EndUserCatalogue`,
`EndUserPages`). The files under `tr/` are the review copies for the Product Owner, the data protection officer and legal:
each heading is a catalogue key and `EndUserCatalogueDocsTest` fails when a copy and the catalogue differ. Change both
together and bump `catalogue.version` (currently `tr-1`) with every text change.

| File | Where it is shown |
|---|---|
| `tr/notice_first_use.md` | first use of an AI platform through the gateway (web banner, IDE first-run notification) |
| `tr/block_page.md` | the 403 block page per reason kind, its footer, and the API error message |
| `tr/personal_account_block.md` | the login-step block for a personal (non-corporate) account (Q-6) |
| `tr/coaching_warn.md` | the coaching page shown after a WARN verdict (out of band) |
| `tr/stream_terminated.md` | the message delivered when a streamed response is aborted |
| `tr/labels.md` | the class and reason labels inserted into the texts above |
| `tr/exception_request.md` | the justification form text; not in the product catalogue yet (the exception workflow for non-fail-closed rules is not built) |

## Placeholders

Configured at runtime from the environment (`RWSAFE_ENDUSER_<NAME>`, an uncommitted ConfigMap; never a literal in the
repository): `{{controller_name}}` (the data controller's legal name), `{{dpo_contact}}`, `{{policy_link}}` (rendered
as text, never as a link), `{{retention_metadata}}`, `{{retention_redacted}}`, `{{retention_raw}}` (whole days). A value
that is too long, holds a control character or a placeholder, or (for a retention figure) is not a number is ignored.

Filled by the product: `{{class}}` and `{{reason}}` (a label from `tr/labels.md`, never the value), `{{platform}}` (the
platform id), `{{ref}}` (the correlation id the employee can quote; letters, digits and `-` only), `{{notice_version}}`.

Every text and every value is HTML-escaped; a page has an inline style, a Content-Security-Policy that loads nothing,
and no script, link or external resource.

## Notice version and acknowledgement (PC-1, C12)

The notice version is `catalogue.version` plus the first 8 hex digits of SHA-256 over the rendered notice without its
own version (for example `tr-1-0a1b2c3d`), so a change to a text or to a configured value is a new version and every
user acknowledges again. While a configured value is missing the notice has no version, is not shown, and no
acknowledgement can match it: content capture stays off for everyone (SR-PRIV-10).

An acknowledgement (C12) records the user's pseudonym, the notice version, the date and the source (`banner`,
`ide_first_run`, `directory_attribute` for the HR policy acknowledgement imported from the directory with its version
and date (Q-35), `gateway_credential_issue`). It is proof that the duty to inform was met, never consent (Q-32).

## Review items (Product Owner and data protection officer)

The catalogue marks these with `LEGAL-REVIEW LR-n`; the wording is in use until the review changes it.

| Id | Key | What to confirm |
|---|---|---|
| LR-1 | `notice.raw.text` | the unmodified-content clause matches the capture mode approved per platform and group (Q-4, Q-5) |
| LR-2 | `notice.basis.text` | the legal basis per data class (art. 5/2-ç, 5/2-f) and that explicit consent is not a basis (Q-32) |
| LR-3 | `notice.transfer.text` | the cross-border transfer wording and the art. 9 instrument per vendor (Q-33) |
| LR-4 | `notice.retention.text` | the configured retention figures (Q-5) and the deletion statement |
| LR-5 | `notice.rights.text` | the art. 11 rights wording, the application channel and the effect of an objection |
| LR-6 | `block.class.noexception` | that no exception exists for fail-closed classes (PC-5, ADR-010), as a promise to employees |
| LR-7 | `notice.acknowledge.text` | the acknowledgement is proof of notice, not consent (Q-32); the HR acknowledgement with the same version counts (Q-35) |
