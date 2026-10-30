# Design-freeze council seats

Three independent seats, the same lenses as the kickoff council, each a fresh-context read-only reviewer (`roles/REVIEWER.md`)
that reads only the files its brief names, inside this repository, and returns consent / dissent / questions-for-the-PO
tables plus its verbatim instruction list. Material is masked documentation only; no prompt bodies exist in the repository.

| Seat | Script | Brief |
|---|---|---|
| Privacy and compliance | `consult_fable.py --brief tools/review/council_seats/SEAT_PRIVACY_COMPLIANCE.md --output docs/reviews/FREEZE_<date>_SEAT_FABLE_PRIVACY_COMPLIANCE.md` | reads ADR-009, MASKING, DATA_CLASSES, RAW_CONTENT_ACCESS, PIA, REGULATORY_MAPPING, i18n, OPEN_QUESTIONS, COUNCIL_RESPONSE §2 |
| Offensive security | `consult_fable.py --brief tools/review/council_seats/SEAT_OFFENSIVE.md --output docs/reviews/FREEZE_<date>_SEAT_FABLE_OFFENSIVE.md` | reads THREAT_MODEL, SECURITY_REQUIREMENTS, BYPASS_CATALOGUE, ICAP spec, ADR-004..008, PLATFORM_MATRIX §3–4, OUT_OF_SCOPE, PENETRATION_TEST_PLAN, COUNCIL_RESPONSE §3 |
| Platform and architecture | `consult_argon.py --brief tools/review/council_seats/SEAT_PLATFORM.md --output docs/reviews/FREEZE_<date>_SEAT_ARGON_PLATFORM.md` | reads ARCHITECTURE, ADR-001..003, 010, 011, ICAP spec, PORTS, CAPACITY, HARDENING, DEPLOY runbook, SHIP plan, deploy/rwsafe, COUNCIL_RESPONSE §1 |

The architect runs them only after the PO says go, then answers every dissent in `COUNCIL_RESPONSE.md` (new section) and
moves open items to `OPEN_QUESTIONS.md`. The PO accepts the freeze with a decision record.
