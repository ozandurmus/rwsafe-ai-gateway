# ProxySG and Broadcom guide for phase 0 (run by the Product Owner)

**Status:** LIVE operator guide for ROADMAP phase 0 (PO decision Q-20, Q-21 in
`docs/design/PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: the PO is the proxy administrator and performs
every step; the session prepares the steps and reads only what comes back). Menu paths and CLI commands are
**UNVERIFIED** against the installed SGOS release until step 1 records the version; where a path differs, use the
equivalent screen and note the difference in the return template.

## 0. Rules for every step

- Production changes: **none** in sections 1 to 4 (read and export only). Section 5 is a lab-only policy change limited to
  one lab client, done under your own change process, and removed after the test.
- Never paste into chat or the repository: addresses, host names of the estate, user or account names, tenant IDs,
  corporate domains, policy text with any of these, certificate subjects, serial numbers or raw log lines. Answer with
  yes/no, counts, version shapes (`7.3.x`) and vendor-published names (the platform domains in section 3 are public vendor
  endpoints and may be written).
- Raw exports (access logs, configuration) stay outside the repository folder, for example under `~/rwsafe-phase0/` on
  your machine, and are deleted when the measurement is recorded.
- What comes back to the session is the filled template in section 7 and the script output of section 2. The session
  records them in `docs/product/PLATFORM_MATRIX.md` §1, `docs/operations/CAPACITY_AND_SLO_MODEL.md` §3 and ADR-006 §4 with
  the date, replacing UNVERIFIED marks only with what you measured.

## 1. ProxySG capability record (read only)

Open the Management Console (or Management Center for the appliance) and answer each row. A CLI alternative is `show
version` and `show configuration`; if you export configuration, pass it through `tools/hosta/mask.sh` before anyone else
reads it, and copy only the answer, never the text.

| # | Question | Where to look (UNVERIFIED path) | Answer shape |
|---|---|---|---|
| 1.1 | SGOS release | Statistics > System > version, or `show version` | `7.3.x` / `7.4.x` (major.minor only) |
| 1.2 | Is Secure ICAP (ICAP over TLS) available on this release? | Configuration > Content Analysis (or External Services) > ICAP > a service > "Secure ICAP" option | yes / no |
| 1.3 | Can the appliance present a **client certificate** on Secure ICAP (mTLS)? | same service: TLS/SSL profile with a client keyring | yes / no / unclear |
| 1.4 | ICAP "maximum object size" for a service, and what happens above it | ICAP service > Sense settings / object size; the error action in the policy (`icap_error_code`, `max_file_size_exceeded`) | the size in MiB; deny or allow above it |
| 1.5 | Preview size offered to ICAP servers | ICAP service > preview / "Send preview" | bytes, or "server-chosen" |
| 1.6 | Fail open or fail closed per service, and on which errors | ICAP service and the policy's ICAP error handling | per service: open / closed; error classes listed |
| 1.7 | Health check settings for ICAP services | Health Checks > the ICAP service | interval, failures before down |
| 1.8 | Connection and transaction timeouts for ICAP | ICAP service > timeouts | seconds; option names as shown |
| 1.9 | Is HTTP/2 enabled for client-side intercepted traffic? | Configuration > Proxy Settings > HTTP/2 (or the SSL proxy service) | yes / no |
| 1.10 | WebSocket handling for intercepted HTTPS | policy: WebSocket rules / proxy services | allowed / denied / not configured |
| 1.11 | Identity sent to ICAP | ICAP service > "Send client address / authenticated user / groups" | which of the three; user format **shape** only: `DOMAIN\user`, `user@realm`, LDAP DN, or other |
| 1.12 | Is SSL interception on for the AI category? | SSL Intercept layer in the Visual Policy Manager | yes / no / partial |
| 1.13 | Is UDP 443 (QUIC) blocked for clients? | firewall policy or proxy rule | yes / no / unknown |

## 2. Masked access-log measurement (Q-30, CAPACITY §3)

1. Export seven days of the main access log in W3C format (the format that starts with a `#Fields:` line) to
   `~/rwsafe-phase0/logs/`. If your log format does not include `cs-categories`, `cs-bytes` or `cs(User-Agent)`, export
   anyway: the script reports which fields are absent.
2. From the repository folder, run:

```bash
python3 tools/proxysg/access_log_shapes.py ~/rwsafe-phase0/logs/*.log* > ~/rwsafe-phase0/shapes.md
```

3. If the "AI category labels seen" section says nothing matched, find the exact AI category name in the console
   (Configuration > Content Filtering > categories) and re-run with `--ai-category "<that name>"`. Category names are the
   vendor's taxonomy, not estate data.
4. Read `~/rwsafe-phase0/shapes.md` yourself first. It holds counts, buckets and platform labels only; the script refuses
   to print if an address- or e-mail-shaped value would appear. Paste it into the chat.
5. Delete the raw logs when the session confirms the numbers are recorded.

What it measures: requests per platform, hour, method, status class, proxy action, request and response size buckets,
time-taken buckets, client classes (browser, VS Code, JetBrains, Claude Code, Codex CLI, SDKs), WebSocket upgrades,
distinct users (below five shown as `<5`), and for uncategorised traffic the number of hosts and how many of them carry
LLM-API path shapes (the relay signal behind Q-30). It never prints a host outside the vendor list, a user, an address, a
path or a user-agent string.

## 3. SSL-interception bypass audit (read only; council SEC-7)

In the Visual Policy Manager, open the SSL Intercept layer(s) and any "do not intercept" lists or category exemptions. For
each vendor domain below, answer **intercepted**, **bypassed** or **not matched by any rule**:

| Platform | Vendor domains to check |
|---|---|
| Claude | `claude.ai`, `api.anthropic.com`, `console.anthropic.com` |
| GitHub Copilot | `github.com`, `api.github.com`, `api.githubcopilot.com`, `*.githubcopilot.com`, `copilot-proxy.githubusercontent.com` |
| OpenAI | `chatgpt.com`, `auth.openai.com`, `api.openai.com`, `platform.openai.com` |
| Google Gemini | `gemini.google.com`, `accounts.google.com`, `*.googleapis.com` (note separately `generativelanguage.googleapis.com`, `cloudcode-pa.googleapis.com`) |
| Microsoft | `login.microsoftonline.com`, `login.microsoft.com`, `login.windows.net`, `login.live.com`, `copilot.microsoft.com` |
| Devin, Windsurf | `app.devin.ai`, `api.devin.ai`, `windsurf.com`, `*.codeium.com` |

Also answer: is **uncategorised** traffic intercepted (yes / no)? Is there a broad exemption for `*.google.com`,
`*.googleapis.com`, `*.github.com` or Microsoft 365 categories (yes / no per item)? Report the answers only; never paste
the policy text.

## 4. Entra tenant restrictions status (Q-21; read only)

1. In the Microsoft Entra admin center, open External Identities > Cross-tenant access settings > Tenant restrictions
   (UNVERIFIED path): is a **tenant restrictions v2** policy configured? yes / no.
2. In the ProxySG policy, search for `Restrict-Access-To-Tenants`, `Restrict-Access-Context`,
   `sec-Restrict-Tenant-Access-Policy`, `X-GoogApps-Allowed-Domains` and `ChatGPT-Allowed-Workspace-Id`: is any of them
   already injected today? yes / no per header, and for which user population (all, a group, none).

## 5. Vendor header verification on a lab client (phase 0, lab only; needs lab tenants, Q-34)

Goal: prove that each header blocks a non-corporate sign-in and allows the corporate one, before phase 1 deploys them on
the pilot group (ADR-007). Do this only from one lab client, under your change process, and remove the rule afterwards.
SSL interception must be on for the hosts named. The CPL below is a template (**UNVERIFIED** syntax for the installed
release); the values in angle brackets are filled only on the appliance, never in this repository.

```text
define action rwsafe_lab_entra
  set(request.header.Restrict-Access-To-Tenants, "<corporate tenant domains or IDs>")
  set(request.header.Restrict-Access-Context, "<corporate directory ID>")
end
define action rwsafe_lab_msa
  set(request.header.sec-Restrict-Tenant-Access-Policy, "restrict-msa")
end
define action rwsafe_lab_google
  set(request.header.X-GoogApps-Allowed-Domains, "<corporate Google Workspace domains>")
end
define action rwsafe_lab_chatgpt
  set(request.header.ChatGPT-Allowed-Workspace-Id, "<corporate ChatGPT workspace IDs>")
end

<Proxy>
  client.address=<lab client> url.domain=login.microsoftonline.com action.rwsafe_lab_entra(yes)
  client.address=<lab client> url.domain=login.microsoft.com       action.rwsafe_lab_entra(yes)
  client.address=<lab client> url.domain=login.windows.net         action.rwsafe_lab_entra(yes)
  client.address=<lab client> url.domain=login.live.com            action.rwsafe_lab_msa(yes)
  client.address=<lab client> url.domain=google.com                action.rwsafe_lab_google(yes)
  client.address=<lab client> url.domain=chatgpt.com               action.rwsafe_lab_chatgpt(yes)
```

Tests per vendor, each answered pass / fail:

| Test | Expected |
|---|---|
| Sign in with a corporate account | allowed |
| Sign in with a personal account (consumer Microsoft, gmail, personal ChatGPT) | blocked by the vendor's own page |
| Sign in with another organisation's account (lab tenant B) | blocked |
| Open `gemini.google.com` with a personal Google account | blocked (verifies the UNVERIFIED Gemini coverage) |
| A client-supplied copy of the header is overwritten, not appended | the vendor sees only the proxy's value (check with the lab tenant's sign-in logs) |

## 6. Broadcom support case (Q-20)

Open a case with Broadcom support from your support portal account with this text (fill the bracketed parts on the
portal only):

```text
Subject: Cloud SWG forwarding a web category to an on-premises ICAP server

We run ProxySG [release] on premises with ICAP REQMOD/RESPMOD to an in-house content-analysis server for the
"[AI category name]" category. We are evaluating Cloud SWG for off-network users. Questions:
1. Can Cloud SWG act as an ICAP client toward a customer-operated ICAP server reachable over a private connection or the
   internet (REQMOD and RESPMOD), for a single category only?
2. If yes: supported transports (Secure ICAP with a client certificate?), preview and 204 support, maximum object size,
   fail-open/fail-closed options, and the latency budget you recommend.
3. If no: is there a supported pattern (connector, Content Analysis service, policy forwarding to an on-premises proxy) that
   delivers the same category's traffic to our on-premises ProxySG for ICAP processing?
4. Which authenticated identity attributes (user, groups) does Cloud SWG pass in that path, and in what format?
Please cite the product documentation for each answer.
```

Record the case number only in your own notes; bring back the answers in your words.

## 7. Return template (paste into the chat)

```text
1.1 SGOS: 7.x.x
1.2 Secure ICAP: yes/no        1.3 mTLS client cert: yes/no/unclear
1.4 max object size: __ MiB, above it: deny/allow
1.5 preview: __ bytes          1.6 fail mode per service: __
1.7 health check: __ s, __ failures        1.8 timeouts: connect __ s, transaction __ s (names: __)
1.9 HTTP/2: yes/no   1.10 WebSocket: __   1.11 identity: client-ip/user/groups, user shape: __
1.12 AI category intercepted: yes/no/partial   1.13 QUIC blocked: yes/no/unknown
2   shapes.md pasted: yes
3   per domain: intercepted/bypassed/not matched; uncategorised intercepted: yes/no; broad exemptions: __
4   Entra TRv2: yes/no; headers already injected: __
5   lab results per vendor: __ (or "waiting for lab tenants")
6   Broadcom answers: __
```
