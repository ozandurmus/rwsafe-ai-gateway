# Pre-pilot independent penetration test plan

**Status:** DRAFT for design freeze. Answers brief 10.5 ("a pre-pilot independent penetration test plan covering ICAP
fuzzing and agent tampering") and the offensive seat's note that weekly ZAP does not cover ICAP or the agent channel.

## 1. Scope and timing

Independent tester (not the implementation team; internal red team or an external firm under NDA), against the
**preview namespace** on HOST-A with synthetic data only, after the MVP's own gates are green and before the pilot group
moves to REQMOD fail-closed. Duration 2 weeks. Nothing against ProxySG or production AI tenants; a lab ProxySG or an ICAP
client harness is provided.

## 2. In scope

| Area | Tests |
|---|---|
| ICAP listener | protocol fuzzing beyond the CI corpus (stateful: Preview/100-Continue/ieof sequences, Encapsulated offset lies, chunk-size lies, header folding, huge header counts, slowloris, connection floods, TLS downgrade and client-certificate bypass attempts on 11344, source-allowlist evasion via spoofed addresses) ; verdict correctness under malformed input (never a 204 on a crash path); memory and CPU behaviour (direct-buffer exhaustion) |
| Detection | the BYPASS_CATALOGUE rows plus the tester's own encodings; measured FN/FP on their corpus |
| Policy snapshot | tamper with the signed snapshot, replay an old snapshot, feed an unsigned one; attempt to make the engine serve without a snapshot |
| Gateway (if deployed to preview) | credential theft and replay, SSRF via model/host fields, header injection, quota bypass, key leakage in errors |
| Admin UI/API | OWASP web tests (authn, authz, CSRF, IDOR on case/grant ids, stored XSS via captured prompts, CSV injection via exports, SIEM injection), role escalation, masked-role leakage (their own canaries), raw-access grant bypass, DSAR search misuse as an oracle |
| Agent channel (if present) | fake device certificate, update tampering, body exfiltration via the reporting API, rate-limit bypass, local privilege escalation on a test endpoint |
| Namespace isolation | from a compromised rwsafe pod (tester-provided): reach `ui2*` services, the registry, the kubelet, Secrets of other namespaces; PSA and NetworkPolicy effectiveness |
| Operations | rollout under attack load (does the drain hold), disk-fill behaviour (watermarks), log and heap for bodies |

## 3. Out of scope

Production ProxySG, production AI tenants, neXus workloads (only reachability from rwsafe is tested), social engineering,
denial of service against HOST-A's network uplink.

## 4. Rules

Synthetic identities and canaries only; the tester receives masked documentation (this repository) and a preview
kubeconfig scoped to the preview namespace; findings reported by location and class, never by value; a HIGH or CRITICAL
finding blocks the pilot until fixed and re-tested; every finding becomes a root-cause log entry and, where applicable,
a bypass-catalogue row with a test.

## 5. Deliverables

Report in `docs/reviews/PENTEST_<date>.md` (sanitised), re-test confirmation, the tester's fuzz corpus merged into the
CI corpus, and a PO decision record accepting any residual.
