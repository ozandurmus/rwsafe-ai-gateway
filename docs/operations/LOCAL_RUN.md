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

## What the engine does not do yet

Secure ICAP (11344, mutual TLS), the signed policy snapshot pulled from the control plane, per-identity in-flight caps
and the pod-wide body semaphore, the drain window with `Connection: close`, the verdict spool, decompression and base64
layer decoding, the file pipeline, login-step tenant rules, shape fingerprints per flow, and metrics. Each is a row of
ICAP spec §2 to §8 that a later slice implements.
