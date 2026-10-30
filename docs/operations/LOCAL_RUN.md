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

It also starts an in-memory LDAP directory on loopback with three synthetic users, one per role: `synthetic-admin`
(`security_admin`), `synthetic-viewer` (`viewer`) and `synthetic-aiview` (`replay_viewer`, the masked session). The
control plane listens on `127.0.0.1:8080` (admin API) and `127.0.0.1:8092` (the data plane's ingestion route only), and
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
Traffic (filters for window, platform, verdict, service and a `USR-` pseudonym; click a row for the event), Event detail
and Health. Signed in as `synthetic-aiview`, every page carries the masked-view chip and passes the masking funnel.

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
Every secret is a mounted file; none is a property value. Without the key file ingestion answers 503 and stores nothing;
without the dictionary the masked role gets 503.

## What the engine does not do yet

Secure ICAP (11344, mutual TLS), the signed policy snapshot pulled from the control plane, per-identity in-flight caps
and the pod-wide body semaphore, the drain window with `Connection: close`, the verdict spool, decompression and base64
layer decoding, the file pipeline, login-step tenant rules, shape fingerprints per flow, and metrics. Each is a row of
ICAP spec §2 to §8 that a later slice implements.
