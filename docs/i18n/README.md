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
`{{policy_link}}`, `{{dpo_contact}}` (filled from configuration, never a literal here), `{{exception_link}}`.
