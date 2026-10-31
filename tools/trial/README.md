# Local end-to-end trial

One command that lets the Product Owner see the product work on a Mac: a chat page where a prompt with a synthetic
identifier goes through the real ICAP engine, a fake AI provider that shows exactly what it received, and the decision
in the admin UI. The Turkish step list for the Product Owner is [`DENEME.md`](DENEME.md).

No container runtime, no Squid, no TLS interception, no corporate certificate and no real AI provider. Everything
listens on and connects to `127.0.0.1` only. Requirements: JDK 21, Node.js 22.12 or later (the frontend's npm packages
are installed from the local npm cache when `frontend/node_modules` is missing), Python 3 standard library, `curl`.

```bash
tools/trial/run_trial.sh     # starts everything in the background, waits for each part, prints the two URLs
tools/trial/stop_trial.sh    # stops everything by PID file
python3 -m unittest discover -s tools/trial -p 'test_*.py'    # the tests (about 20 s with a compiled engine)
```

## What runs

| Step | Component | Address | Log under `tools/trial/.run/` |
|---|---|---|---|
| 1 | Gradle (`--offline`) compiles and writes the two classpaths through `classpath.init.gradle` | - | `build.log` |
| 2 | Control plane, the `:control:runDev` runner (embedded PostgreSQL, in-memory LDAP, synthetic sample events) | `:8080` admin API, `:8091` snapshot feed, `:8092` event ingestion | `control.log` |
| 3 | ICAP engine, the `:dataplane:runIcap` main class, fed by the signed snapshot (`dev-snapshot.pem`), events to `:8092`, spool and snapshot cache under `.run/` | `:1344` ICAP, `:9401` `/ready` and metrics | `dataplane.log` |
| 4 | Admin UI, the Vite dev server (proxies `/api` to `:8080`) | `:5173` | `frontend.log` |
| 5 | `mock_ai.py`, the fake provider (OpenAI chat completions shape; replies `Sağlayıcıya ulaşan metin: <what arrived>`) | a free port, written to `.run/mock_ai.port` | `mock_ai.log` |
| 6 | `trial_proxy.py`, the chat page and proxy stand-in | `:8765` | `trial_proxy.log` |

Each JVM is started directly from its classpath (not through a Gradle daemon), so its PID file names the server and
`stop_trial.sh` stops it with SIGTERM: the engine drains and ships its events, the control plane closes PostgreSQL. A
component whose PID file names a live process is left running, so `run_trial.sh` is safe to repeat. A port held by
another process stops the start with a message naming the port. Set `TRIAL_GRADLE_OFFLINE=0` to let Gradle download
missing dependencies; `RWSAFE_SAMPLE_EVENTS` and `RWSAFE_DEV_PG_PORT` pass through to the control plane runner.
Sign-in credentials are regenerated at every control plane start in `java/control/build/dev/credentials.txt`.

## What the proxy stand-in does

On "Gönder" `trial_proxy.py` builds the request a vendor would receive after the corporate proxy decrypted it:
`POST https://api.openai.com/v1/chat/completions` (absolute-form target, `Host: api.openai.com`, the openai platform row
of `policy/registry-seed.yaml`, so the engine classifies it as openai, surface api, step chat) with the chat completions
JSON body. It sends it as REQMOD to `icap://127.0.0.1:1344/reqmod-ai` with `Allow: 204`, `X-Client-IP: 127.0.0.1` and
a synthetic `X-Authenticated-User` (base64, as `tools/icap/replay.py` sends it), using the ICAP reader of `replay.py`.
Then, like the proxy:

| Engine answer | Decision shown | Sent to `mock_ai` |
|---|---|---|
| `204 No Content` | allowed | the original body |
| `200` with a request (`req-hdr`) | masked, with the class tokens found (`[REDACTED:TCKN]`, ...) | the rewritten body |
| `200` with a response (`res-hdr`, HTTP 403) | blocked, with `X-RWSAFE-Reason` and the `X-RWSAFE-Ref` reference (the event id) | nothing; the block answer is shown (HTML in a sandboxed iframe, JSON as text) |
| anything else, or no connection | no decision | nothing (fail closed) |

The block answer is JSON for an API client; the page's "Tarayıcı isteği gibi gönder" box adds `Accept: text/html` so
the engine returns its Turkish HTML block page instead. The request carries no `Authorization` header (no key exists).

Guards: `require_loopback` refuses any address other than the literal `127.0.0.1` before every ICAP connection, every
forward to the provider and the listener bind; the page's API answers only requests whose `Host` (and `Origin`, when
sent) is the page itself, with a JSON content type. Neither server logs a prompt or a body (method, path and status
only). The example prompts carry a checksum-valid identity number, a valid TR account number and a secret-shaped key
generated at start with `random.SystemRandom`; nothing identifier-shaped is written to disk or committed.

## Tests

`test_trial.py` (standard library `unittest`):

- the loopback-only guard: the literal address only, the constructor, the per-connection re-check, and the page API
  refusing a foreign `Origin` or `Host`;
- fail closed: an engine error (ICAP 500) and an unreachable engine forward nothing;
- against the real engine (started by the test from the classpath the init script writes, built-in development
  snapshot, free loopback ports): a plain question is allowed unchanged (204, the provider receives the original body),
  a synthetic identity number is replaced by `[REDACTED:TCKN]` before the provider, and a secret-shaped key is blocked
  (403, JSON for the API client, HTML for the browser form) with nothing reaching the provider.
