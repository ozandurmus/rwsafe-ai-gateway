# ADR-008: Guardrail engine, build versus integrate

Status: PROPOSED
Date: 2026-10-30
Answers: brief 5C (detectors, prompt injection, actions, policy registry), 7 (stack), 10.4 (policy lifecycle, model and
rule-pack supply chain); council ARCH-6, ARCH-7, Argon P1-4, offensive P1 "model and rule-pack supply chain", SEC-4

## Context

Brief 5C asks for standard classifiers for secrets, PII, customer data, internal names and source-code exfiltration, plus
prompt-injection and jailbreak detection, with allow/warn/redact/block actions and a versioned, approval-gated policy
registry. HOST-A has no GPU and shares 16 vCPU with neXus. Lakera Guard is a hosted API (and reportedly now part of Cisco
AI Defense, UNVERIFIED); Check Point, Purview, Netskope and Zscaler bundle detection inside their platforms; none can be
called from the inline path (latency, data leaving the host, PRIV-3). Prompt bodies may not leave HOST-A for detection.

## Decision

1. **Build the deterministic tier; integrate open components for the ML tier; never call a cloud detector inline.**
2. **Tier 1, inline, deterministic** (`rwsafe-detect` library, Java, RE2/J + Aho-Corasick + checksum validators), budget
   2 CPU-ms per 4 KiB and 12 CPU-ms per 64 KiB (CAPACITY §4), classes:
   - secrets: vendor key shapes (Anthropic, OpenAI, Google, GitHub, AWS, Azure, GCP service-account JSON, Slack, Stripe,
     JWT, PEM blocks, generic high-entropy with context keywords); the gitleaks rule set is the seed, converted to RE2
     syntax and tested;
   - Turkish and sector identifiers: TCKN (checksum), TR IBAN (mod-97), TR phone, credit card (Luhn), customer-number
     formats supplied by the PO (digests of format rules, not samples), Turkish name dictionary (for the masking layer,
     not for blocking);
   - estate names: hosts, domains, projects, users from the uncommitted estate dictionary. **Matching is whole-token over
     keyed digests** of normalised tokens (OFF2-9): the data plane never holds the plaintext dictionary in memory, so a
     memory disclosure reveals digests only; the documented limitation is that a partial or concatenated name is not
     detected inline, and the worker's full-text pass (which holds the dictionary) catches it after the fact;
   - internal addresses: RFC 1918 and the estate's ranges;
   - source-code exfiltration: language detection by token statistics, repository markers (license headers, package
     names, internal module prefixes from the estate dictionary), size thresholds per surface;
   - special-category keyword lists (health, religion, union, sexual life, biometric) for the C5 flag;
   - normalisation before detection (SEC-4): Unicode NFKC, zero-width and tag-character stripping, homoglyph folding to
     ASCII for the Latin and Turkish alphabets, Base64/hex/URL decoding to depth 2, archive listing to depth 2;
   - prompt-injection **lexical** signals (instruction-override phrases, role-play jailbreak templates, delimiter floods,
     encoded payload markers): on ordinary prompts they **warn** and tag; on `tool_result`, function-result and fetched
     web-content blocks of agentic surfaces (CLI, IDE, MCP) the high-confidence patterns may **block** at REQMOD and
     **abort** at RESPMOD, policy-configurable, monitor first (OFF2-7, Q-31);
   - client-chosen "metadata" fields (file names, tool and MCP server names, `model`, URL path and query, user agent, SSE
     event names, upstream error messages, the coaching-page justification text) are **content-grade**: length-capped,
     control characters stripped, untrusted framing applied in every view and digest-or-enum in the SIEM (OFF2-8);
3. **Tier 2, asynchronous, ML** in `rwsafe-worker`: an ONNX-runtime classifier for prompt injection and jailbreak
   (candidates: open models in the ProtectAI/deberta-v3 family, UNVERIFIED licence and quality for Turkish), run on the
   **redacted** text after the response, bounded 200 ms per item, 2 threads, circuit breaker on queue depth 1000; its
   verdict is an alert and feeds policy tuning; it may become inline only if a measured CPU budget on HOST-A allows and
   the PO accepts the latency (OPEN Q-22). Model files: **safetensors or ONNX only, never pickle**; downloaded through
   the corporate proxy, hash-pinned in the repository, signed by the release pipeline, licence and provenance recorded
   (offensive P1 supply chain).
4. **Policy registry** (AGENTS.md 6): YAML fixtures under `policy/` compiled into a signed snapshot with a **monotonic
   version** (OFF2-11) by the control plane (`policy_snapshot` table: version, hash, approver, mode); entry fields: id,
   platform, surface, step, class, action (`allow|warn|redact|block`), mode (`monitor|enforce|shadow`), groups (AD group
   pseudonym ids), exceptions with expiry, fail behaviour reference (ADR-010), source document pointer. Changes go through
   PR + approval in the UI (four eyes for `enforce` changes on fail-closed classes) and are audited; the data plane loads
   only a snapshot whose signature verifies and whose version is higher than the active one. **Fail-closed classes have no
   `monitor` mode**: a new rule on them is `shadow` (recorded next to the live verdict) while the seed baseline enforces;
   an exception on them needs `privacy_officer` + `security_admin` and a recorded legal instrument (PC-5).
5. **Actions**: `allow` (204), `warn` (204 + coaching event), `redact` (200 with class tokens), `block` (403 coaching
   page). Every action is audited with the policy version; a user justification flow on the coaching page creates a
   time-boxed exception request for `security_analyst` approval (brief 10.4).
6. **Evaluation**: a labelled **synthetic** corpus (never captured content, PRIV-8) per class and per bypass technique
   (BYPASS_CATALOGUE), with target false-negative and false-positive rates recorded in SECURITY_REQUIREMENTS; the pilot
   acceptance depends on these numbers.
7. **Shared library**: the detector library compiles to the JVM (data plane, worker) and to WASM (the browser extension of
   ADR-006) from one rule source, so verdicts match across paths.

## Alternatives considered

- Lakera Guard or another hosted guard API inline: data leaves the host, latency 50 ms+ plus network, dependency on a
  third party for the fail-closed classes; rejected (kept in COMPETITIVE_REFERENCE as a design reference for categories).
- A local LLM judge inline: no GPU, hundreds of ms per call; rejected (ARCH-7).
- Microsoft Presidio or similar PII frameworks: Python runtime and spaCy models on the hot path; the deterministic
  recognisers are re-implemented in Java/RE2 instead; Presidio's recogniser list is a reference.
- `java.util.regex` with timeouts: still backtracking; rejected (AC-3).

## Consequences

- Two artefacts to build and test: the detector library (with fuzzing and the bypass corpus) and the policy compiler.
- The ML tier is optional for the MVP; the deterministic tier is the MVP.

## Evidence and UNVERIFIED facts

Lakera Guard API reference (docs.lakera.ai `/v2/guard`, categories `prompt_injection`, `jailbreak`); Check Point,
Purview, Netskope, Zscaler product pages (vendor claims). UNVERIFIED: Lakera's ownership; open prompt-injection model
licences and Turkish performance.

## Open questions

Q-22 (ML tier inline or async), Q-23 (customer-number formats and the Turkish name dictionary source).
