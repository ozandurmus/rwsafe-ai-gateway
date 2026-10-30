# Threat model (STRIDE per external interface)

**Status:** DRAFT for design freeze (SSDF PW.1/PW.2). Interfaces: ICAP listener, LLM API gateway, admin UI/API, agent
channel, SIEM/notification egress, plus the storage and the review surface the offensive seat added ("stored prompts are
hostile input", "the masked AI reviewer is a target"). Each threat names the control and the test that proves it
(`SECURITY_REQUIREMENTS.md` ids). Residual risks are listed for PO acceptance.

## 1. Assets

Corporate AI keys (gateway Secret); the policy snapshot signing key; the privacy HMAC key; the capture-store KEK and data
keys; captured content (C3, C4); findings digests; identities and sessions; the audit ledger; the policy registry; the
estate dictionary (real names); the ProxySG trust (client CA); the node shared with neXus.

## 2. ICAP listener (1344/11344 from ProxySG)

| STRIDE | Threat | Control | Test |
|---|---|---|---|
| S | A host on the network pretends to be ProxySG and injects `X-Authenticated-User` to frame a user or to feed false captures | Secure ICAP with mTLS, source allowlist in NetworkPolicy and in the engine, `identity_source=proxy_claim` label, plain 1344 only in the pilot window | SR-ICAP-1, SR-ICAP-2 |
| S | Surrogate identity mix-up on VDI/NAT | shared-address classification, `identity_shared_address` label, no per-user enforcement decisions on shared addresses beyond tenant rules | SR-ICAP-3 |
| T | Malformed ICAP/HTTP frames to corrupt parsing, confuse `Encapsulated` offsets, smuggle a second request | strict decoder with limits, fuzzing (Jazzer), parse failure → explicit verdict | SR-DP-3, SR-DP-4 |
| R | A block or allow cannot be attributed later | verdict events never dropped, policy version in every record, trigger audit | SR-AUD-1 |
| I | Prompt bodies leak through logs, metrics, heap dumps, error pages | PRIV-10 controls, log scanner test, heap dump off | SR-PRIV-6 |
| I | Oversize body makes ProxySG bypass inspection | ProxySG max-size rule set to deny; rwsafe limit below it | SR-ICAP-4 |
| D | ReDoS, decompression bomb, slow-loris, connection flood from a compromised client via the proxy | RE2/J only, decompression caps, per-connection byte cap, timeouts, 1 000 in-flight cap, 503 to ProxySG | SR-DP-1, SR-DP-2, SR-DP-5 |
| D | rwsafe outage takes AI work down | 2 replicas, PDB, drain, ProxySG fail setting per ADR-010 | SR-AVL-1 |
| E | A crafted request makes the engine call back into the control plane or the Internet | the data plane has no egress except the control plane (NetworkPolicy); no URL fetching inline | SR-DP-6 |

## 3. LLM API gateway (443 by host name)

| STRIDE | Threat | Control | Test |
|---|---|---|---|
| S | Stolen client credential used from another device | short-lived credentials bound to user and device fingerprint, re-issued via directory login, revocable | SR-GW-1 |
| S | Open relay: anyone on the network uses the corporate key | credential required for every request; anonymous requests 401; per-team quota | SR-GW-2 |
| T | Client supplies `model`, `base_url`-like fields or headers to route elsewhere | fixed upstream allowlist, model and region allowlist per data class, header stripping/allowlisting, no SSRF (no client-supplied URLs) | SR-GW-3 |
| R | Cost or usage dispute | token counts and cost per request recorded, exportable | SR-GW-4 |
| I | Prompt cache or response cache shared across users/tenants | no shared cache keyed without the credential; vendor prompt-cache headers passed through per credential only | SR-GW-5 |
| I | Upstream key leaks via error messages or logs | key never logged, error bodies from upstream sanitised, key rotation runbook | SR-GW-6 |
| D | Token-flood or runaway agent loops burn quota (OWASP LLM10) | per-team and per-credential rate and token quotas, circuit breaker per upstream | SR-GW-7 |
| E | Gateway compromise yields corporate keys | keys in a Secret mounted only to gateway pods, PSA restricted, read-only root, no shell in the image, rotation | SR-GW-8 |

## 4. Admin UI and API (443 by host name)

| STRIDE | Threat | Control | Test |
|---|---|---|---|
| S | Session fixation, cookie leak to the sibling product on the shared parent domain | `__Host-` cookies, host-only CSP, HSTS, no parent-domain cookies | SR-ADM-1 |
| S | LDAP injection or weak break-glass | parameterised LDAP filters, break-glass accounts with hardware-token-grade passwords, business-hours confirmation, audited | SR-ADM-2 |
| T | CSRF on policy changes | CSRF token + SameSite, four-eyes on fail-closed class changes | SR-ADM-3 |
| T | Stored XSS from captured prompts rendered in the review UI (SEC-5) | content rendered as text in a sandboxed element, no HTML, CSP without inline scripts, CSV formula injection escaped on export | SR-ADM-4 |
| T | Prompt injection against an AI agent reading the masked view | the masked API frames content as untrusted (`X-RWSAFE-Content: untrusted`, JSON wrapper, no instructions in content fields), bodies not served to the masked role by default | SR-PRIV-3 |
| R | Admin denies a policy change | trigger-enforced audit with actor fingerprint, SIEM copy | SR-AUD-1 |
| I | Masked role sees a real identifier | masking funnel, canary probe incl. Turkish identifiers, 503 fail-closed | SR-PRIV-1, SR-PRIV-2 |
| I | Re-identification through stable pseudonyms and raw-value filters | masked search over pseudonymised fields only, no raw-value filter, k-anonymity threshold in analytics, rwsafe-own HMAC key | SR-PRIV-4 |
| I | A single admin reads raw content | JIT grant, four eyes, reason code, time limit, DPO notice, SIEM copy | SR-PRIV-5 |
| D | Export of a huge table | bounded exports, async job | SR-ADM-5 |
| E | Role escalation via group binding tampering | group → role bindings signed by the role-binding key (neXus pattern), audited | SR-ADM-6 |

## 5. Agent channel (later phase)

| STRIDE | Threat | Control | Test |
|---|---|---|---|
| S | A fake agent reports false verdicts or pulls the snapshot | mTLS with MDM device certificate, per-device token | SR-AGT-1 |
| T | Tampered extension or agent binary | signed packages, pinned update server, policy-installed only | SR-AGT-2 |
| I | The agent exfiltrates bodies | agent never sends bodies by default; server rejects body fields without the capture conditions | SR-AGT-3 |
| D | Agent flood | per-device rate limits | SR-AGT-4 |
| E | Local privilege escalation via the agent service | user-space only, no root service, MDM-installed configuration | SR-AGT-5 |

## 6. SIEM, notification and directory egress

| STRIDE | Threat | Control | Test |
|---|---|---|---|
| T | CR/LF or ANSI injection into syslog/SIEM from prompt-derived fields | all exported strings sanitised (control characters stripped, length-capped), bodies never exported | SR-SIEM-1 |
| I | Sensitive content in SIEM | only C1/C2/C6/C7 fields; a schema test proves no body field exists | SR-SIEM-2 |
| I | Syslog in clear | TLS 6514 preferred; UDP 514 only with PO acceptance | SR-SIEM-3 |
| S | Mail spoofing via the relay | fixed sender, relay allowlist | SR-NOT-1 |
| I | LDAP credentials | bind account in a Secret, LDAPS, least privilege | SR-ADM-2 |

## 7. Storage and the shared node

| STRIDE | Threat | Control | Test |
|---|---|---|---|
| I | Cluster admin or host root reads the capture store or Secrets | k3s Secrets encrypted at rest (verified on), envelope encryption with KEK in a Secret, raw-content JIT model; residual risk: host root can read Secrets through the API: **accepted by the PO with the "no HSM" residual risk (privacy seat)** | SR-PRIV-7 |
| D | rwsafe fills the disk and starves neXus | byte cap, 75/85 % watermarks, no disk-pressure toleration, lower PriorityClass, quota | SR-HOST-1 |
| D | neXus fills the disk and starves rwsafe | rwsafe degrades to metadata-only, enforcement continues | SR-HOST-2 |
| T | Backups restore expired data | deletion receipts replayed on restore | SR-PRIV-8 |
| E | Container escape from rwsafe reaches neXus | PSA restricted, no hostPath, caps dropped, seccomp, read-only root, NetworkPolicy | SR-HOST-3 |

## 8. Supply chain

| STRIDE | Threat | Control | Test |
|---|---|---|---|
| T | Malicious model or rule pack | safetensors/ONNX only, hash-pinned, signed, licence recorded | SR-SC-1 |
| T | Dependency tampering | Gradle lockfiles + verification metadata, Trivy, SBOM | SR-SC-2 |
| T | Image tampering between build and deploy | digest pinning, signature + provenance verification at deploy | SR-SC-3 |

## 9. OWASP Top 10 for LLM Applications 2025 mapping

| OWASP | Where rwsafe meets it |
|---|---|
| LLM01 Prompt injection | Tier-1 lexical signals (warn), Tier-2 async classifier, RESPMOD detection of injection in returned content, untrusted framing for the masked AI reviewer |
| LLM02 Sensitive information disclosure | DLP classes, redaction before persistence, masking funnel, no bodies in SIEM |
| LLM03 Supply chain | §8 |
| LLM04 Data and model poisoning | captured content never trains anything (PRIV-8); rule packs signed |
| LLM05 Improper output handling | inert rendering (SEC-5), export escaping, SIEM sanitising |
| LLM06 Excessive agency | MCP allowlists and tool-call inspection where visible (brief 10.4), managed settings |
| LLM07 System prompt leakage | gateway strips and never logs system prompts; findings on system-prompt fields are class-tagged |
| LLM08 Vector and embedding weaknesses | not applicable (no RAG in rwsafe) |
| LLM09 Misinformation | out of scope (user-facing content quality) |
| LLM10 Unbounded consumption | gateway quotas, rate limits, ICAP limits |

## 10. Residual risks for PO acceptance

1. Host root and cluster admin can read Secrets and PVCs (no HSM). 2. Streaming responses cannot be redacted, only
aborted; bytes already forwarded are gone. 3. Pinned apps and off-net users are invisible until the agent phase. 4.
Pseudonymisation is not anonymisation: the masked role's data is still personal data under KVKK (privacy seat); handled by
the DSAR path and retention, not by claiming anonymity. 5. The MV3 extension is best-effort blocking.
