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
version; with rollout stage `all` and mode `enforce` the next snapshot carries it (format 1 has no group targeting, so a
staged or monitor version is shown, approved and simulated but not sent). The Simulate button counts how the stored
events carrying the class would change under a proposed action.

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

## What the engine does not do yet

Decompression and base64 layer decoding, the file pipeline, login-step tenant rules, shape fingerprints per flow, and
group claims selecting policy on Secure ICAP connections. Each is a row of ICAP spec §2 to §5 that a later slice
implements.
