# ADR-009: Data model, retention and privacy

Status: PROPOSED
Date: 2026-10-30
Answers: brief section 2 (Prompt content), 4A product rules 1 to 7, 5B (store per policy), 6 (Privacy); council PRIV-1,
PRIV-4, PRIV-5, PRIV-6, PRIV-7, PRIV-8, PRIV-9, PRIV-10, ARCH-2 (dedup, byte cap), SEC-5 (stored prompts are hostile input)

## Context

The PO decided that prompt and response capture is on from the start, role-restricted, masked in AI-agent views,
retention-bounded and audited. The privacy seat requires a legal basis per data class, no stored matched values,
redaction before persistence, crypto-shredding, a DSAR path, and no prompt body for the masked role or external reviewers
by default. The platform seat requires content-addressed deduplication and a hard byte cap. HOST-A's disk is at 80 %.

## Decision

### 1. Data classes (the vocabulary every other document uses)

| Class | What | Store | Default retention (OPEN Q-5) | Masked role sees |
|---|---|---|---|---|
| `C1 metadata` | who (user pseudonym + fingerprint), platform, surface, tenant, model, time, sizes, flow fingerprint, identity source, proxy claim state | PostgreSQL | 400 days (audit alignment) | yes, pseudonymised |
| `C2 verdict` | action, classes hit, offsets and digests of findings (never the value), policy version, confidence | PostgreSQL | 400 days | yes |
| `C3 redacted content` | the prompt/response text after redaction of every detected secret, PII, customer identifier and estate name, tokenised (`[REDACTED:TCKN]`) | capture store (encrypted chunks) | 90 days | **no body by default**; derived features only (PRIV-6); exception by signed record |
| `C4 raw content` | the original body, only when the policy for that platform and group allows, the user has an accepted notice and the disk watermark permits | capture store, envelope-encrypted per record with its own data key | 30 days | never |
| `C5 special-category hits` | that a special-category class (health, religion, union, biometric, sexual life) was detected: class and digest only, never text | PostgreSQL (flag on C2) | 400 days | class only |
| `C6 DLP findings` | class, offset, length, digest of the matched span, detector id, rule-pack version | PostgreSQL | 400 days | yes (no value exists) |
| `C7 audit` | every admin and raw-access action, trigger-enforced | PostgreSQL, append-only | 10 years (sector audit-trail norms, UNVERIFIED exact BDDK figure, REGULATORY_MAPPING) | yes, pseudonymised |
| `C8 SIEM copies` | CEF/LEEF/HEC events: C1, C2, C6, C7 fields only; **never C3/C4** | the SIEM (external) | the SIEM's own; deletion requests are forwarded as events (PRIV-4) | n/a |
| `C9 exports` | CSV/XLSX/PDF produced by a user: masked for masked roles, watermarked with the downloader fingerprint | not stored; the download is audited | — | masked |
| `C10 backups` | encrypted sets of PostgreSQL and key material; capture chunks not backed up by default | platform backup set | 14 days | n/a |
| `C11 evaluation corpus` | synthetic prompts and sanitized protocol frames only; **never captured content** (PRIV-8) | repository fixtures | permanent | n/a |
| `C12 notice acceptance` | user, notice version, time, surface | PostgreSQL | as long as the user is in scope + 400 days | yes |

### 2. Processing before persistence (PRIV-7)

```
body ──► normalise (SEC-4) ──► detect (deterministic classes) ──► REDACT every finding in place ──► C3 text
                                       │                                    │
                                       └─► C6 findings (class, offset, digest = HMAC_k(value))  └─► chunk + dedup + encrypt ──► capture store
raw C4 path (only if allowed): body ──► chunk (content-defined, 8–64 KiB) ──► SHA-256 per chunk ──► new chunks encrypted
   under a per-record data key (AES-256-GCM) wrapped by the store KEK (Secret) ──► manifest (record → chunk list) in PostgreSQL
```

Nothing matched is ever written: the digest lets an analyst ask "did this same secret appear elsewhere" without
storing it. The HMAC key for digests is rwsafe's own, separate from the pseudonym key and the store KEK (key separation
as in neXus C1 §6.1).

### 3. Deduplication and the byte cap (ARCH-2)

Coding agents resend the same repository context every turn. Chunks are content-addressed, so a repeated chunk stores a
manifest reference, not bytes. The store keeps a byte counter; `MAX_STORE_BYTES` (80 GiB) is enforced by the worker's
retention job (oldest C4 first, then C3) and by the data plane's watermark signal (`CAPACITY_AND_SLO_MODEL.md` §2). Chunk
reference counts make deletion exact: a chunk is shredded when its last manifest is deleted.

### 4. Deletion and legal hold (PRIV-4)

- Retention expiry and DSAR erasure run the same path: delete manifests and rows, decrement chunk references, crypto-shred
  orphaned data keys, write a **deletion receipt** (record id, classes, time, reason), send a deletion event to the SIEM.
- Backups are restored only through a procedure that replays receipts newer than the backup (ADR-002 §5).
- **Legal hold** is a flag on the record and on its chunks' reference count; held records are excluded from retention and
  erasure until the hold is lifted by the `privacy_officer` with a case id; every hold is audited.

### 5. Access to content (PRIV-9, brief 4A rule 6)

| Content | Who | How |
|---|---|---|
| C3 redacted text | `security_analyst` on an incident with a case id and reason code; `privacy_officer` for a DSAR | audited read; the UI frames the text as untrusted (SEC-5: rendered inert, no HTML, no formulas, CR/LF and ANSI stripped before display and export) |
| C4 raw | nobody alone. Just-in-time grant: requester (`security_admin` or `privacy_officer`) + approver (the other role), reason code, case id, time limit ≤ 4 h, DPO notified at grant time, out-of-band audit copy to the SIEM immediately, grant revocable | the decrypted view is watermarked, not downloadable, and every page view is a trigger-audited row |
| masked role (`replay_viewer`, AI agents) | never C3 or C4 bodies; C1, C2, C6 pseudonymised; derived features (class counts, token counts, flow fingerprints) | HTTP 503 if the masking dictionary or key is missing |
| external reviewers | derived features and synthetic fixtures only (AGENTS.md 4.7) | authorised scripts |

### 6. Search (PRIV-5)

Two searches: the masked search over pseudonymised fields and derived features (no raw-value filter, no "does this
value exist" oracle), and the **DSAR search** available to `privacy_officer` only, which resolves a person's identifier
(employee id, e-mail, or a customer number found inside content via its digest) to records, audited with the case id; it
never shows bodies without the §5 grant.

### 7. Logs, metrics, traces, heap (PRIV-10)

Request and response bodies never enter logs, exceptions, metrics labels, trace attributes or heap dumps: the body types
are `ByteBuf`s released after processing, `toString()` of every body-bearing type is redacted, Logback has a body-pattern
scanner appender in tests that fails the build if a body fixture leaks, `-XX:-HeapDumpOnOutOfMemoryError`, JFR off in
production, Spring error pages never include request content. A log-scanner e2e test (AC-6) grep-scans all pod logs for
canary bodies after the ICAP e2e Job.

### 8. Secondary use (PRIV-8)

Captured content is never used to train or tune classifiers, never aggregated into productivity analytics per person,
never shared with another product. Team-level analytics apply a k-anonymity threshold of 5 (privacy P1 "small-team
aggregation"). This is a policy-registry constant and a test.

## Alternatives considered

- Bodies in PostgreSQL: rejected (ADR-002).
- Storing matched values for analyst convenience: rejected (PRIV-7; the store would be the organisation's largest secret
  archive).
- Raw retention by default: rejected by the privacy seat and by HOST-A's disk; the PO decides the MVP mode in Q-4.

## Consequences

- `docs/security/DATA_CLASSES_AND_RETENTION.md`, `RAW_CONTENT_ACCESS.md` and `MASKING_AND_PRIVACY.md` are the detailed
  companions; this ADR fixes the vocabulary and the invariants.
- Storage growth is bounded and measurable per class.

## Evidence and UNVERIFIED facts

- neXus artefact-store envelope pattern, pseudonym registry, masking funnel (read 2026-10-30).
- UNVERIFIED: the sector regulator's exact audit-trail retention figure (REGULATORY_MAPPING marks it).

## Open questions

Q-4 (MVP capture mode), Q-5 (retention days, DPO identity, raw-access approvers), Q-6 (BYOD and personal-use policy).
