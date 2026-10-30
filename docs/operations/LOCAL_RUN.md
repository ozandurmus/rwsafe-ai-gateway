# Running rwsafe locally

Local runs use synthetic traffic only. Nothing here touches HOST-A, neXus or ProxySG.

## ICAP engine (data plane)

Requirements: JDK 21 and Python 3. From the repository root:

```bash
./java/gradlew -p java :dataplane:runIcap
```

The engine listens on `127.0.0.1:1344` with the built-in development snapshot (secrets block; TCKN, TR IBAN and payment
card numbers are redacted; the AI-category flow is fail-closed). Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `RWSAFE_ICAP_BIND` | `127.0.0.1` for `runIcap`, `0.0.0.0` in the image | listen address |
| `RWSAFE_ICAP_PORT` | `1344` | listen port (plain ICAP, exception H-2) |
| `RWSAFE_CONTROL_EVENTS_URL` | unset | control-plane verdict-event endpoint (`POST /internal/v1/verdict-events`); unset counts and discards events |
| `RWSAFE_SPOOL_DIR` | unset | directory for the verdict spool (emptyDir in the pod); unset, an outage holds events in the queue and fail-closed flows block when it fills |
| `RWSAFE_ICAPS_PORT` | `11344` | Secure ICAP listener, opened only when the three TLS variables below are set |
| `RWSAFE_TLS_CERT`, `RWSAFE_TLS_KEY`, `RWSAFE_TLS_CLIENT_CA` | unset | server certificate chain, its PKCS#8 key and the CA that issued the proxy's client certificate (PEM files; never committed) |
| `RWSAFE_SNAPSHOT_URL` | unset | the control plane's signed snapshot endpoint (`docs/architecture/POLICY_SNAPSHOT_CONTRACT.md`); set, the engine is not ready until the first valid snapshot |
| `RWSAFE_SNAPSHOT_PUBLIC_KEYS` | unset | comma-separated `<key id>.pem` public keys that verify snapshots |
| `RWSAFE_SNAPSHOT_CACHE` | unset | directory for the last good snapshot, verified again at start |
| `RWSAFE_METRICS_PORT` | `9401` | `GET /metrics` (Prometheus text, fixed labels only), `GET /ready` and the preStop drain `GET`/`POST /admin/drain` (starts the drain, answers after the 15 s serve window) |
| `RWSAFE_SHARED_ADDRESS_PREFIXES` | unset | client-address prefixes shared by many users (VDI, terminal servers): 256 transactions in flight instead of 32 |
| `RWSAFE_GROUP_CLAIM_ENCODING` | unset (disabled) | how the proxy encodes `X-Authenticated-Groups`: exactly `plain` or `base64` (below); unset or any other value disables group claims, so every transaction takes the strictest policy |

In a second terminal, replay the synthetic sample traffic:

```bash
python3 tools/icap/replay.py
```

Each line is one scenario built from the fixtures under `java/dataplane/src/test/resources/fixtures/icap/`: a clean
ChatGPT prompt (204, unchanged), a Claude API prompt with a customer TCKN (200, `[REDACTED:TCKN]`), a Copilot prompt with
an IBAN (200, `[REDACTED:IBAN]`), a Gemini prompt with a cloud key (403 block), a key placed after the 4 KiB preview
boundary (still blocked, OFF2-1) and a clean prompt decided inside the preview (204). Identifiers and keys are generated
at runtime and never written to disk.

Any ICAP client works as well, for example `c-icap-client` against `icap://127.0.0.1:1344/reqmod-ai`.

### Scoped rules (snapshot format 2)

A format 2 snapshot adds group-scoped rules on top of the `ANY` class actions (POLICY_SNAPSHOT_CONTRACT.md, PO decision
Q-39). The engine reads the proxy's `X-Authenticated-Groups` claim only when `RWSAFE_GROUP_CLAIM_ENCODING` says how it
is encoded, and trusts it only on the Secure ICAP listener; it never guesses the encoding per value (PR 20 review D-01).
Which encoding the estate proxy uses is UNVERIFIED.

- `plain`: the header value is a comma-separated list of short group names (no commas inside a name, PR 20 review Q-2),
  its octets read as UTF-8.
- `base64`: the whole header value is standard base64 (RFC 4648 section 4 alphabet, padding required) of that same
  UTF-8 list.

Each name is compared in one form shared with the snapshot (`GroupNames`): white space stripped, Unicode NFC, Turkish
`İ`, `I` and `ı` folded to `i`, lower case (`Locale.ROOT`), a combining dot above after `i` removed, NFC again. A header
that is repeated, holds a control character, a name over 256 characters, more than 256 comma-separated tokens (empty
and repeated ones counted), octets that are not UTF-8 or invalid base64 is no claim. On plain ICAP, with group claims
disabled, or with no readable claim, each class takes the strictest of `ANY` and every enforce scoped rule. The verdict
event names the rules (`appliedRuleIds`, `monitorRuleIds`), never the groups.

The quickest local check is the synthetic end-to-end suite, which runs one engine with a stricter, a looser and a monitor
rule over both listeners:

```bash
./java/gradlew -p java :dataplane:test --tests '*ScopedPolicyEndToEndTest' --tests '*GroupClaimTest'
```

By hand: the built-in development snapshot has no scoped rules, so point the engine at a control plane that issues
format 2 (`RWSAFE_SNAPSHOT_URL`, `RWSAFE_SNAPSHOT_PUBLIC_KEYS`), set `RWSAFE_GROUP_CLAIM_ENCODING=plain`, approve a
group-scoped version there, and send a REQMOD
with `-x "X-Authenticated-Groups: <synthetic group>"` from `c-icap-client`. On port 1344 a stricter group rule applies to
every user and a looser one has no effect; group selection needs the Secure ICAP listener (`RWSAFE_TLS_*`) and a client
that presents a certificate issued by `RWSAFE_TLS_CLIENT_CA`.

## Control plane and admin UI

Requirements: JDK 21 and Node.js 22.12 or later. No container runtime is needed: the development runner starts an
embedded PostgreSQL 16 (the same binaries the tests use) whose data stays under `java/control/build/dev/postgres`.

Terminal 1, the control plane:

```bash
./java/gradlew -p java :control:runDev
```

On first start the runner generates, under `java/control/build/dev/` (ignored by git, owner-only files):

| File | What it is |
|---|---|
| `privacy-hmac.key` | a development privacy HMAC key (32 random bytes); pseudonyms and subnet labels are keyed by it |
| `estate-dictionary.txt` | a development estate dictionary with one synthetic term |
| `credentials.txt` | the synthetic directory users and their passwords, regenerated at every start |
| `break-glass-initial-password` | the break-glass account's initial password, written once when the account is created |
| `snapshot-signing.key` | a development Ed25519 key (PKCS#8 PEM) that signs the policy snapshot, key id `dev-snapshot` |
| `snapshot-public-keys/dev-snapshot.pem` | its public half (X.509 SubjectPublicKeyInfo PEM) for a local data plane |

It also starts an in-memory LDAP directory on loopback with four synthetic users, one per role: `synthetic-admin`
(`security_admin`), `synthetic-officer` (`privacy_officer`), `synthetic-viewer` (`viewer`) and `synthetic-aiview`
(`replay_viewer`, the masked session). The control plane listens on `127.0.0.1:8080` (admin API), `127.0.0.1:8091` (the
signed policy snapshot only) and `127.0.0.1:8092` (the data plane's ingestion route only); each internal route answers
404 on every other port. An empty policy registry is seeded from `policy/registry-seed.yaml`, and the runner
fills an empty database with 6 000 synthetic verdict events through the real ingestion path (validation,
pseudonymisation, subnet masking). Environment variables: `RWSAFE_SAMPLE_EVENTS` (default 6000; 0 for none) and
`RWSAFE_DEV_PG_PORT` (default 54329). To start again from an empty database, stop the runner and delete
`java/control/build/dev/postgres`.

Terminal 2, the admin UI:

```bash
cd frontend && npm ci && npm run dev
```

Open `http://127.0.0.1:5173` and sign in with a user from `java/control/build/dev/credentials.txt`. The Vite server
proxies `/api` to the control plane, so the session and CSRF cookies are same-origin as behind the ingress. Screens:
Overview (headline counts, events per hour by verdict group, verdict mix, per-platform counts, DLP finding classes),
Traffic (filters for window, platform, verdict, service and a `USR-` pseudonym; click a row for the event), Event detail,
Policies, Platforms and Health. The UI is Turkish by default; the user menu switches to English and remembers the choice
for that user in this browser (PO decision Q-38). Signed in as `synthetic-aiview`, every page carries the masked-view chip
and passes the masking funnel.

The policy registry by hand: sign in as `synthetic-admin`, open Policies, select a class (for example TCKN), submit a new
version (a fail-closed class is never offered Allow or Warn) and approve it as security administrator; then sign in as
`synthetic-officer` in another browser profile and give the privacy officer approval. The second approval activates the
version. A version with the scope Everyone and mode `enforce` becomes the snapshot's `classActions`; an Everyone version
in monitor mode is shown, approved and simulated but not sent. The Simulate button counts how the stored events carrying
the class would change under a proposed action (it re-decides the Everyone baseline only).

A group-scoped version (PO decision Q-39, snapshot format 2): in the new-version form choose "Seçilen dizin grupları"
(Selected directory groups), type the short directory group name (no commas) and press Enter for each group (1 to 32;
use synthetic names such as `GRP-ALPHA` locally, never a real directory group in a committed file), then submit and give
the two approvals as above. Names are stored, compared and sent in one normal form (trimmed, NFC, the Turkish and Latin
i forms folded to `i`, lower case), so `GRP-ALPHA` is listed as `grp-alpha`; two names that normalise alike are refused.
The next snapshot lists it in `scopedRules` as `class.<CLASS>@<version>` with its groups and mode (monitor versions are
sent too); the Everyone version keeps applying beside it, and the Policies table shows both scopes as chips. The same as
a request:

```bash
curl -s -b cookies.txt -H "X-XSRF-TOKEN: $XSRF" -H 'Content-Type: application/json' \
  -d '{"action":"REDACT","mode":"enforce","scope":{"kind":"GROUPS","groups":["GRP-ALPHA"]},"reasonCode":"PILOT_GROUP"}' \
  http://127.0.0.1:8090/api/v1/policy/rules/class.SECRET/versions
```

Every class is fail-closed today, so a group may be looser than everyone only as REDACT where everyone is BLOCK; ALLOW
and WARN are refused in every scope. `rolloutStage` is optional and, when sent, `all` (the percentage stages are retired).

Retiring a platform (PO decision Q-40): signed in as `synthetic-admin`, open Platforms, press "Kullanımdan kaldır" on an
active row, write the reason, press "Devam et", read the consequences and confirm with "Evet, kullanımdan kaldır". No
second approval is needed. The row stays listed, greyed, with the time, the administrator's pseudonym and the reason; the
next snapshot leaves the platform out; the ledger (`audit_event`, action `policy.platform_retire`) names the
administrator and carries the reason. The last active platform cannot be retired (`RETIRE_WOULD_NOT_COMPILE`). Bringing a
platform back is a new version under the two approvals. As a request:
`POST /api/v1/policy/rules/platform.<id>/retirement` with `{"reason":"..."}` (security administrator only; 403 for the
viewer, the privacy officer and the masked role). A retirement also supersedes the platform's pending drafts, so an
approval given before it never counts afterwards. A reason (retirement or withdrawal) is refused when it holds an
identifier: an address, an e-mail address, a phone, card, IBAN or TCKN number, a secret shape or an estate term
(`REASON_HOLDS_IDENTIFIER`, `ESTATE_NAME_REFUSED`).

Withdrawing a group scope (PR 21 decision Q-41): signed in as `synthetic-admin`, open Policies, select the class, press
"Geri çek" beside an active group-scoped version, write the reason, press "Devam et" and confirm with "Evet, onaya
gönder". The request appears as a new pending version ("Sürüm N için geri çekme") with its own approval steps; it takes
the same two approvals as an activation (security administrator, then `synthetic-officer` as privacy officer). With the
second approval the scoped version becomes `withdrawn`, the request stays active as the scope's marker, and the next
snapshot no longer lists the scoped rule, so those groups follow the rule for everyone again. Until then the version
keeps applying. As a request: `POST /api/v1/policy/rules/class.<CLASS>/versions/<version>/withdrawal` with
`{"reason":"..."}`, then the usual approvals on the returned version. Drafts for different scopes (or modes) of one rule
wait side by side; a new draft replaces only the pending version of its own rule, mode and scope.

The signed snapshot, as the data plane pulls it:

```bash
curl -si http://127.0.0.1:8091/internal/v1/policy/snapshot
curl -si -H 'If-None-Match: "1"' http://127.0.0.1:8091/internal/v1/policy/snapshot
```

The answer carries `ETag: "<version>"`, `X-RWSAFE-Key-Id: dev-snapshot` and `X-RWSAFE-Signature: ed25519:<base64>` over the
exact body bytes; the second call is 304 while the version is unchanged. A new version is issued when an approval changes
the active rules and, with no change, at least every 6 hours (a scheduled re-sign, so the data plane never reaches its
24-hour staleness limit); every issued snapshot is recorded in `policy_snapshot` and ledgered. A local data plane verifies
it with `RWSAFE_SNAPSHOT_PUBLIC_KEYS=java/control/build/dev/snapshot-public-keys/dev-snapshot.pem` and
`RWSAFE_SNAPSHOT_URL=http://127.0.0.1:8091/internal/v1/policy/snapshot` (POLICY_SNAPSHOT_CONTRACT).

Terminal 3 (optional), real verdicts from the ICAP engine into the same UI:

```bash
RWSAFE_CONTROL_EVENTS_URL=http://127.0.0.1:8092/internal/v1/verdict-events ./java/gradlew -p java :dataplane:runIcap
```

```bash
python3 tools/icap/replay.py
```

The six replay scenarios appear at the top of the Traffic screen within a second, with their verdicts and finding
classes; the synthetic identity claim and client address are stored only as a `USR-` pseudonym and a masked subnet.

### Against an existing PostgreSQL

`:control:runControl` runs the control plane alone. It reads `RWSAFE_DB_URL` and `RWSAFE_DB_USER`, the database password
from a config tree (`RWSAFE_SECRETS_DIR`, default `/run/secrets/rwsafe/`, file `spring.datasource.password`),
`RWSAFE_PRIVACY_HMAC_KEY_FILE`, `RWSAFE_ESTATE_DICTIONARY_FILE`, and for the directory `RWSAFE_LDAP_URL`,
`RWSAFE_LDAP_BIND_DN`, `RWSAFE_LDAP_BIND_PASSWORD_FILE`, `RWSAFE_LDAP_USER_SEARCH_BASE` and
`RWSAFE_LDAP_USER_SEARCH_FILTER` (group-to-role bindings as `rwsafe.identity.ldap.group-roles[<group DN>]=<role>`).
`RWSAFE_BREAK_GLASS_ENABLED=true` with `RWSAFE_BREAK_GLASS_PASSWORD_FILE` creates the break-glass account at first start.
Behind an ingress, `RWSAFE_FORWARD_HEADERS=native` with `RWSAFE_TRUSTED_PROXIES` (a regular expression naming the ingress
addresses only) gives the login throttle the real client address; both are off by default.
The policy registry and snapshot read `RWSAFE_POLICY_SEED_FILE` (the committed `policy/registry-seed.yaml`, imported
once into an empty registry; without it no snapshot can be issued and the feed answers 503), `RWSAFE_SNAPSHOT_SIGNING_KEY`
(the Ed25519 private key file, PKCS#8 PEM, from a Secret), `RWSAFE_SNAPSHOT_KEY_ID` (the id the data plane knows the public
key by; when unset, the key file's name without its extension), `RWSAFE_SNAPSHOT_REFRESH` (re-sign interval, default and
maximum `PT6H`), `RWSAFE_SNAPSHOT_FEED_PORT` and `RWSAFE_SNAPSHOT_FEED_BIND` (default `127.0.0.1:8091`). Without the
signing key the feed answers 503 `SNAPSHOT_SIGNING_UNAVAILABLE`, never an unsigned snapshot. Approvers come from the
directory: bind a group to `privacy_officer` as to any other role.
Every secret is a mounted file; none is a property value. Without the key file ingestion answers 503 and stores nothing;
without the dictionary the masked role gets 503.

### SIEM export

The control plane exports verdict events and audit-ledger rows (ADR-009 C8: C1, C2, C6 and C7 fields only, never a body)
to syslog over TLS (RFC 5425 octet framing, CEF or LEEF 1.0 payload) and/or Splunk HEC over HTTPS. It is off by default.

| Variable | Default | Meaning |
|---|---|---|
| `RWSAFE_SIEM_ENABLED` | `false` | turns the exporter on |
| `RWSAFE_SIEM_START_FROM` | `earliest` | for a destination without a watermark: `earliest` (everything stored) or `latest` (skip the stored verdict events; ledger rows always export from the first one) |
| `RWSAFE_SIEM_SYSLOG_HOST` | empty (off) | syslog receiver; with `RWSAFE_SIEM_SYSLOG_PORT` (default `6514`) |
| `RWSAFE_SIEM_SYSLOG_FORMAT` | `cef` | `cef` or `leef` |
| `RWSAFE_SIEM_SYSLOG_CA_FILE` | `/etc/rwsafe/siem/ca.crt` | PEM bundle the receiver's certificate must chain to |
| `RWSAFE_SIEM_HEC_URL` | empty (off) | `https://host:port` (the path `/services/collector/event` is added) or the full endpoint URL |
| `RWSAFE_SIEM_HEC_TOKEN_FILE` | `/run/secrets/rwsafe-siem/hec-token` | the HEC token, a mounted Secret file |
| `RWSAFE_SIEM_HEC_CA_FILE` | `/etc/rwsafe/siem/ca.crt` | PEM bundle for the HEC endpoint |
| `RWSAFE_SIEM_HEC_INDEX` | empty | target index; empty uses the token's default |

Tuning stays in `rwsafe.siem.*` (`poll-interval` 2 s, `queue-capacity` 10000, `page-size` 500 (the queue holds at least
two pages), `batch-size` 200, `backoff-initial` 1 s, `backoff-max` 2 min). In the cluster the real destinations, the
index and the CA bundle live in the uncommitted ConfigMap `rwsafe-siem-destination` and the token in the Secret
`rwsafe-siem-credentials` (`deploy/rwsafe/contracts/runtime-contracts.json`); the Deployment wiring and the NetworkPolicy
egress to the SIEM follow in the deploy lane.

- **Fail closed (AGENTS.md 4.10)**: without rwsafe's privacy key or the estate dictionary no exporter starts. A
  destination with a missing CA bundle or token, a non-HTTPS URL, an unknown format or a host name that is not a plain
  lower-case label is not started. The Health screen's `siem` row is `DOWN` and names the reason.
- **Transport (SR-SIEM-3)**: TLS 1.3/1.2 only, trust exactly the configured CA bundle (never the JVM store), host name
  verified. There is no UDP and no plain-TCP setting.
- **Fields (SR-SIEM-1, SR-SIEM-2)**: the fixed set in `SiemField`. Each value must match its field's exact shape and
  hold no estate term, otherwise it leaves as `[WITHHELD]`. Users are `USR-` pseudonyms or `system:` actors, the client
  is a masked /24 label, findings are `CLASS:count`. A ledger row key leaves as written only for the listed audited
  tables in their exact key shape (a number, a policy version key, a destination) with no detector hit or estate term.
  An account key becomes the account's `USR-` pseudonym, any other key a keyed `KEY-` pseudonym. Every string is
  stripped of control characters and ANSI sequences (bounded) and length-capped. LEEF values escape `\` and `=`.
- **Order and delivery**: at least once, never a skip. Both exported tables carry `tx_id` (the writing transaction, Flyway
  V7). The exporter reads only rows below the current snapshot's xmin, ordered by (tx_id, id), so a transaction that
  commits late is never overtaken by the watermark; a long transaction pauses the export (backlog) instead. The
  watermark (`siem_watermark`, one row per destination) moves only after the destination acknowledged (syslog: written
  and flushed; HEC: HTTP 200). A restart resumes from it, so the last batch can arrive twice (de-duplicate on
  `externalId`/`eventId`). Creating a destination's watermark is a ledger row (`siem_export.start`, reason
  `START_FROM_EARLIEST` or `START_FROM_LATEST`), exported like every other; a `latest` start records how many verdict
  events it skipped.
- **Overflow and back-off**: the queue is bounded; the reader reads one page per stream only when the queue has room for
  both, otherwise it counts a deferred read. Nothing is dropped and ingestion never waits. Failures back off from 1 s
  doubling to 2 min.
- **Health and metrics**: the `siem` row shows per destination the delivered count, the backlog (committed rows beyond
  the watermark), the queue, the reader's and the sender's failure states separately (`DEGRADED`), the syslog batches
  possibly lost and a `latest` start's skip count. Metrics `rwsafe_siem_*` (labels destination, stream, reason, thread
  only) are rendered by `SiemExportService.prometheus()`; the metrics listener (9400) is not served yet.
- **Audit durability (PO decision Q-SIEM-2)**: RFC 5425 has no acknowledgement. A watcher thread on each syslog
  connection sees the receiver close it. The next batch then goes on a new connection, and a batch flushed on the closed
  connection counts as possibly lost (`rwsafe_siem_batches_possibly_lost_total`, Health). A deployment that relies on the
  SIEM copy of the audit ledger uses HEC, alone or beside syslog.
- **UNVERIFIED (2026-10-30)**: LEEF header and value escaping in the corporate QRadar. Send one test event per format
  before production.

## What the engine does not do yet

The file pipeline (multipart, documents, archives, and files found inside a base64 layer, which are
`UNINSPECTABLE(EMBEDDED_FILE)` for now), hex and other non-base64 layers, gzip inside base64 (BY-ENC-9), decompression on
the streamed RESPMOD path, login-step tenant rules, shape fingerprints per flow. Each is a row of ICAP spec §2 to §5 that a later slice implements. A single declared gzip or
deflate `Content-Encoding` and base64 layers to depth 3 are decoded and scanned (a fourth layer is `UNINSPECTABLE(UNDECODABLE_BLOB)`); `br`, stacked codings and undeclared
compressed bodies stay `UNINSPECTABLE`.
