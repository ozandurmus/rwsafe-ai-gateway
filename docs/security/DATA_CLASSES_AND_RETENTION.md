# Data classes and retention matrix, with the deletion path

**Status:** DRAFT for PO decision (retention figures are recommendations, OPEN_QUESTIONS Q-5). Answers council PRIV-1
(legal basis per class), PRIV-4, PRIV-7, PRIV-8, PRIV-10, brief 4A product rule 6, 6 (Privacy). Vocabulary from ADR-009.
Legal articles are KVKK (Law 6698); the sector rules are in `docs/compliance/REGULATORY_MAPPING.md`. UNVERIFIED legal
readings are marked for the DPO's review; the architect is not counsel.

## 1. Matrix

| Class | Content | Purpose | Legal basis (KVKK) | Store | Retention | Legal hold | Deletion proof | Backups | SIEM |
|---|---|---|---|---|---|---|---|---|---|
| C1 metadata | who (pseudonym + fingerprint), platform, surface, tenant, model, time, sizes, verdict ref | security of information systems, enforcement of the AI-use policy | art. 5/2-ç (legal obligation: sector information-systems rules), 5/2-f (legitimate interest), proportionality per the constitutional-court workplace-monitoring line: prior notice, purpose limitation, no lighter means (UNVERIFIED reading, DPO) | PostgreSQL | 400 d | yes | receipt | yes (14 d sets) | yes |
| C2 verdict | action, classes, policy version, confidence | same | same | PostgreSQL | 400 d | yes | receipt | yes | yes |
| C3 redacted content | prompt/response text after redaction; **not persisted at all when a C5 flag fired** (PC-7) | incident investigation, deterministic rule review inside a case (never ML input; PC-14), evidence | 5/2-f with the art. 10 notice; the C12 acknowledgement is proof of notice and a proportionality control, **never a consent basis** (PC-2) | capture store, encrypted | 90 d | yes | receipt + chunk shred | **no** | **no** |
| C4 raw content | original body | investigation of a confirmed incident only | 5/2-f narrowly, behind the JIT grant; the PIA assesses whether raw is proportionate at all (Q-4) | capture store, envelope-encrypted per record | 30 d | yes | crypto-shred of the data key | **no** | **no** |
| C5 special-category hits | class + digest that art. 6 data appeared | preventing exfiltration of special-category data | art. 6: processing of special-category data itself is avoided (text not stored); the flag is derived metadata (UNVERIFIED reading) | PostgreSQL flag | 400 d | yes | receipt | yes | class only |
| C6 DLP findings | class, offset, length, digest, detector id, pack version | same as C1 | same as C1 | PostgreSQL | **secret-shape digests 400 d; PII and customer-identifier digests 90 d, then a class-only tombstone** (PC-6); digest key rotated yearly | yes | receipt | yes | class only |
| C7 audit | admin and raw-access actions | accountability, sector audit trail | 5/2-ç | PostgreSQL append-only | 10 y (UNVERIFIED sector figure) | n/a | never deleted inside retention | yes | yes |
| C8 SIEM copies | C1/C2/C6/C7 fields | corporate monitoring | 5/2-ç, 5/2-f | the SIEM | the SIEM's; deletion events forwarded | n/a | SIEM-side (external) | n/a | — |
| C9 exports | analyst exports (masked by role, watermarked) | investigation | same as the viewed class | not retained by rwsafe | — | — | download audited | — | — |
| C10 backups | encrypted PostgreSQL dumps + key material | recovery | same as the classes they hold | platform backup set; **off-host target must be in Türkiye** (primary-system reading, PC-13, Q-12) | 14 d | hold flag replicated | restore replays receipts | — | — |
| C11 evaluation corpus | synthetic prompts, sanitized frames | testing | none needed (no personal data) | repository | permanent | — | — | — | — |
| C12 notice acknowledgement | user, notice version, time, source (`banner`, `ide_first_run`, `directory_attribute` imported from the HR policy acknowledgement for IDE/CLI/API users, `gateway_credential_issue`) (PC-2, PC-3) | proof of art. 10 notice | 5/2-ç | PostgreSQL | scope + 400 d | yes | receipt | yes | no |
| C15 case, grant and exception notes | free text by analysts, requesters and users (justification form); detector-scanned and redacted at write (PC-14) | investigation records | 5/2-ç, 5/2-f | PostgreSQL | 400 d | yes | receipt | yes | no |
| C1 content-grade fields | client-chosen metadata: file names, tool and MCP server names, model, URL path and query, user agent, SSE event names, upstream error text (OFF2-8) | as C1 | as C1 | PostgreSQL, length-capped, control characters stripped, untrusted-framed in every view, digest or enum in the SIEM | as C1 | yes | receipt | yes | digest/enum only |
| C13 identity and roles | users, groups (pseudonymised in masked views), role bindings | access control | 5/2-ç, 5/2-f | PostgreSQL | while in scope + 400 d | — | receipt | yes | admin events |
| C14 policy registry | policies, approvals, snapshots | operation | — | PostgreSQL + repository | permanent (versioned) | — | — | yes | changes |

## 2. Deletion path (one path for retention expiry and DSAR erasure)

1. The worker selects records past retention (or named by a DSAR case) that carry no legal hold.
2. For C3/C4: delete the manifest rows, decrement chunk reference counts, **crypto-shred** data keys of orphaned C4
   records, delete orphaned chunks, zero the counters.
3. For C1/C2/C6/C12/C13: delete rows (or pseudonym-only tombstones where a count must survive).
4. Write a **deletion receipt** (record ids, classes, time, reason, case) to the receipts table (C7 class, append-only).
5. Emit a SIEM deletion event so the SIEM can apply its own purge for the same ids.
6. Backups: a restore runs the receipts newer than the backup before the database is opened for service (ADR-002); the
   restore drill (quarterly) proves it (AC-6).

## 3. Legal hold

`privacy_officer` places a hold with a case id; the hold is a flag on records and a reference held on chunks; retention
and erasure skip held items; the hold list is reviewed quarterly; every hold and release is audited and notified to the
DPO group.

## 4. Minimisation rules (design, not policy)

- No class stores a matched sensitive value (PRIV-7).
- Special-category text is never stored (C5 is a flag).
- Blocked personal-login attempts store the event (C1/C2) with class `NON_CORPORATE_ACCOUNT`, never the content and never
  the personal identifier or its digest (PC-9).
- Explicit consent (art. 5/1) is deliberately **not** a basis for any class: in an employment relationship it is neither
  free nor stable (PC-2).
- Team analytics apply k ≥ 5.
- Captured content never trains or tunes anything and never leaves the product (PRIV-8).
- Raw content is off until notice, approval record and disk watermark allow (Q-4).

## 5. What the DPO must confirm (UNVERIFIED legal readings)

The legitimate-interest balancing for C3; whether C5 flags count as processing of special-category data; the sector's
audit-trail retention figure for C7; whether the 5651 "collective use provider" log obligation is met by ProxySG's own
logs or needs rwsafe's C1 (REGULATORY_MAPPING); the VERBIS inventory entries for each class.
