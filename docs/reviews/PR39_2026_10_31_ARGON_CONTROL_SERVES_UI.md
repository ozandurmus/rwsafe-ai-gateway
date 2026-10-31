<!-- Argon consultation 2026-10-31T11:34:28Z, model gemini-4-argon-high, effort high; unaltered output except 21 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| Static serving path traversal & MIME handling ([`AdminUi.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/config/AdminUi.java), [`AdminUiServingTest.java`](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/config/AdminUiServingTest.java)) | **CONSENT (with D-01 on symlinks)** — URL path traversal (`..`, encoded slashes/dots) is blocked by `PathResourceResolver` and verified by tests. Missing `.js`/`.css`/dotted paths return the API's JSON 404 (`application/json`) rather than `index.html`, preventing MIME confusion alongside `X-Content-Type-Options: nosniff`. |
| SPA fallback & route/port confinement ([`AdminUi.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/config/AdminUi.java), [`InternalConnector.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/config/InternalConnector.java), [`SecurityConfig.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/SecurityConfig.java)) | **CONSENT** — `InternalConnector.internalPortFilter` runs at `Ordered.HIGHEST_PRECEDENCE` and returns 404 for all UI paths on the capture sink (8092), snapshot feed (8091), and metrics listener (9400). On 8080, controller mappings take precedence and `AdminUi.spaRoute` excludes `api`, `internal`, `assets`, `metrics`, and any last segment containing a dot. |
| Security headers ([`SecurityConfig.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/SecurityConfig.java), [`frontend/index.html`](file://<workspace-root>/frontend/index.html)) | **CONSENT** — Every admin UI and API response carries `Content-Security-Policy` with `default-src 'self'`, `script-src 'self'` (no `unsafe-inline` or `unsafe-eval`), `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`, and `frame-ancestors 'none'`, plus `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `X-Frame-Options: DENY`. `index.html` loads its module script from `/assets/` with no inline script. |
| Session & CSRF cookie security ([`CookiePolicy.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/CookiePolicy.java), [`application.yaml`](file://<workspace-root>/java/control/src/main/resources/application.yaml), [`SecurityConfig.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/SecurityConfig.java)) | **CONSENT (with D-02 on prefix enforcement)** — Production defaults set `RWSAFE_COOKIE_SECURE=true`, `__Host-rwsafe-session` (`HttpOnly`, `SameSite=Strict`, `Path=/`), and `SameSite=Strict; Secure; Path=/` on the CSRF cookie. Serving the SPA sets no cookie (`SessionCreationPolicy.IF_REQUIRED`). |
| Container image & npm build ([`control.Containerfile`](file://<workspace-root>/deploy/images/control.Containerfile), [`frontend/package.json`](file://<workspace-root>/frontend/package.json), [`frontend/vite.config.ts`](file://<workspace-root>/frontend/vite.config.ts), [`PILOT_RUNBOOK.md`](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md)) | **CONSENT (with D-03 on CA bundle concatenation)** — `ubi9/nodejs-22` is pinned by `linux/amd64` SHA-256 digest; `package.json` pins exact versions; `npm ci --ignore-scripts` verifies lockfile integrity without running lifecycle scripts; `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` are stage-scoped `ARG`s in builder stages only, and the runtime stage copies only `/out/app/` with `0755`/`0644` permissions under `USER 185:0`. |
| Masked role (`replay_viewer`) confinement ([`SecurityConfig.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/SecurityConfig.java)) | **CONSENT** — All `/api/**` authorization matchers precede `.requestMatchers(HttpMethod.GET, "/**").permitAll()`. The masked role remains strictly read-only on `/api/v1/**` and is explicitly denied policy approvals, C3 capture reads (with refusal ledgering), and all mutations. |

---

### (2) DISSENT Table

| Finding ID | File and Line or Symbol | What is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | [`AdminUi.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/config/AdminUi.java#L46-L100) (`AdminUi`, `SpaResolver`) and [`AdminUiServingTest.java`](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/config/AdminUiServingTest.java#L116-L123) | `AdminUi` normalizes `this.dir` lexically (`dir.toAbsolutePath().normalize()`) and relies on `PathResourceResolver.checkResource` over `FileSystemResource`, which checks `getURL().getPath()` (lexical normalization) rather than `toRealPath()`. If a symlink inside `rwsafe.ui.dir` or `rwsafe.ui.dir/assets` points outside `rwsafe.ui.dir`, `PathResourceResolver` follows it and serves the target file. | **P2** | Resolve the canonical root (`Path realRoot = dir.toRealPath()` when present) and override `checkResource(Resource resource, Resource location)` in a resolver used by both `/assets/**` and `/**` to verify `!Files.isSymbolicLink(resource.getFile().toPath())` and `resource.getFile().toPath().toRealPath().startsWith(realRoot)`. Add a symlink escape test case in `AdminUiServingTest.nothingOutsideTheDirectoryIsServed`. |
| **D-02** | [`CookiePolicy.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/CookiePolicy.java#L21-L39) (`CookiePolicy.check`) and [`CookiePolicyTest.java`](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/identity/CookiePolicyTest.java#L11-L24) | `CookiePolicy.check` rejects `__Host-`/`__Secure-` when `sessionSecure == false`, but accepts an unprefixed session cookie name when `sessionSecure == true` (e.g., `CookiePolicy.check("rwsafe-session", true, true)` passes), allowing a Secure deployment to lose `__Host-` origin/path binding if `RWSAFE_SESSION_COOKIE` is overridden. Also, the `@Value` fallback defaults (`JSESSIONID` and `false`) disagree with `application.yaml` (`__Host-rwsafe-session` and `true`). | **P2** | In `CookiePolicy.check`, throw `IllegalStateException` when `sessionSecure && !sessionCookie.startsWith("__Host-")`; align the constructor `@Value` fallback defaults to `__Host-rwsafe-session` and `true`; and add `assertThrows(IllegalStateException.class, () -> CookiePolicy.check("rwsafe-session", true, true))` in `CookiePolicyTest`. |
| **D-03** | [`deploy/images/control.Containerfile`](file://<workspace-root>/deploy/images/control.Containerfile#L40-L41) (`ui` stage `RUN`) | `cat /tmp/corp-ca/*.pem > /tmp/corp-ca.bundle` concatenates PEM files directly; if any `.pem` file lacks a trailing newline, `-----END CERTIFICATE----------BEGIN CERTIFICATE-----` merges onto one line and Node's `NODE_EXTRA_CA_CERTS` parser ignores the affected certificate. | **P2** | Replace `cat /tmp/corp-ca/*.pem > /tmp/corp-ca.bundle` with `awk 1 /tmp/corp-ca/*.pem > /tmp/corp-ca.bundle` so a newline is guaranteed between every PEM file. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| None — no open product or policy ambiguity blocks this PR. | Merge now or apply the three P2 hardening items (D-01, D-02, D-03) in this PR or the next follow-up. |

---

### (4) Verdict

MERGE WITH CORRECTIONS

---

### (5) Verbatim Instructions Received

1. User request:
```text
/plan REVIEW: second independent review of pull request 39 (AGENTS.md section 9, security-sensitive: the admin UI served by
the control plane, security headers, session cookies, the image build), branch `feature/control-serves-ui`
LENS: whether serving the built React admin UI from the control plane keeps the admin API's security (CSP, cookies,
CSRF, port confinement, masked role) and keeps the image build pinned and verified.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any path traversal, symlink escape or MIME
confusion in the static serving; any SPA fallback that shadows an API, internal or metrics route or serves the UI on an
internal port; any missing or weakened security header (CSP without unsafe-inline, frame-ancestors, nosniff); any cookie
setting that lets the session or CSRF cookie travel insecurely in production; any npm step that can run an unpinned
package or install script, or leak the proxy into a layer; and any change that lets the masked role see more. Return
exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong,
severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a
one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim.
Be concrete and short. Never quote or invent an address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8)
- java/control/src/main/java/io/rwsafe/control/config/AdminUi.java
- java/control/src/main/java/io/rwsafe/control/identity/CookiePolicy.java
- the control plane security configuration and port filter (java/control/src/main/java/ files naming "Security" or "Port")
- java/control/src/main/resources/application.yaml
- deploy/images/control.Containerfile
- frontend/package.json, frontend/index.html, frontend/vite.config.ts
- java/control/src/test/java/ files naming "AdminUi" or "CookiePolicy"
- docs/operations/PILOT_RUNBOOK.md (sections 4, 4b, 6, 14)
```

2. Workspace rule (`AGENTS.md`):
- Repository rule loaded from `<workspace-root>/AGENTS.md` (sections 1–14, verbatim in the repository file read first above).

3. Slash command metadata (`/plan`):
```text
The user is requesting that you think and plan carefully before executing the upcoming task.
Carefully research the task, make sure that you and the user are aligned on the goals and requirements,
create a detailed implementation plan artifact, and get user approval on the plan before making any code changes (besides artifacts)
or running any modifying commands.
```
