# End-user texts (Turkish)

The one place in the repository where content is Turkish by design: KVKK article 10 notice validity requires that the
people being informed read it in their language (AGENTS.md section 3). Keys, file names and comments are English. These
are templates for the DPO and legal to finalise; the product renders them from its i18n resources with the notice
version recorded in each acceptance (class C12).

| File | Where it is shown |
|---|---|
| `tr/notice_first_use.md` | first use of an AI platform through the gateway (web banner, IDE first-run notification) |
| `tr/block_page.md` | the 403 coaching/block page body |
| `tr/coaching_warn.md` | the warning shown after a WARN verdict (out of band) |
| `tr/personal_account_block.md` | the login-step block for a personal/non-corporate account |
| `tr/exception_request.md` | the justification form text |
| `tr/stream_terminated.md` | the message delivered when a streamed response is aborted |

Placeholders: `{{class}}` (the DLP class name, never the value), `{{ref}}` (correlation id), `{{platform}}`,
`{{policy_link}}`, `{{dpo_contact}}`, `{{controller_name}}` (the data controller's legal name), `{{retention_metadata}}`,
`{{retention_redacted}}`, `{{retention_raw}}`, `{{notice_version}}`, `{{exception_link}}` (rendered **only** for classes
that are not fail-closed; PC-5), `{{duration_options}}`. All filled from configuration, never a literal here. Rule (PC-1):
any change to a placeholder value or to the text bumps `notice_version` and requires re-acknowledgement.
