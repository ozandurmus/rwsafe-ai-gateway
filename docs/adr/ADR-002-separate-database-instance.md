# ADR-002: Separate PostgreSQL instance

Status: ACCEPTED (PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE, 2026-10-30)
Date: 2026-10-30
Answers: brief section 2 (own database instance), section 4 rule 2, section 5F (audit by triggers, backup and restore);
council ARCH-1 (no synchronous DB on the hot path), PRIV-4 (deletion reaches backups), Argon P0-1

## Context

The PO decided on a separate database instance, never a schema in neXus's database. neXus runs PostgreSQL 16
(`quay.io/sclorg/postgresql-16`, arbitrary-UID image) as a one-replica StatefulSet with a 2 GiB PVC, Flyway as the only
migration authority, two roles (`migrate`, `app`), credentials as mounted files, audit enforced by database triggers
reading per-transaction `set_config` values (actor fingerprint, action id, correlation id). The corporate standard allows
PostgreSQL. HOST-A's disk is the scarce resource.

## Decision

1. **StatefulSet `rwsafe-db`**, PostgreSQL 16, the same sclorg image family and digest discipline as neXus, one replica,
   PVC `rwsafe-db-data` **20 GiB**, ClusterIP Service `rwsafe-db`, reachable only from the control plane and worker pods
   by NetworkPolicy. Roles `rwsafe_migrate` and `rwsafe_app`; credentials generated at creation, patched into the Secret,
   mounted as files; never in a manifest, argument or log.
2. **Flyway** is the only migration authority; every migration is dry-run in `BEGIN/ROLLBACK` on the live database before
   deploy; the control plane runs migrations at start as the migrate role; the data plane has **no database credential**
   at all (ARCH-1: it cannot even open a connection).
3. **What lives in PostgreSQL**: identities and role bindings, policy registry versions and approvals, platform matrix
   rows, request **metadata** (who, platform, tool, tenant, model, time, sizes, verdict, DLP finding classes with offsets
   and digests), capture **manifests** (pointer to the encrypted blob, content hashes, retention class, legal-hold flag,
   key id), audit log, SIEM watermarks, DSAR cases. **What never lives in PostgreSQL**: prompt or response bodies, raw or
   redacted (they live in the encrypted capture store on the PVC as content-addressed chunks), secrets, matched sensitive
   values.
4. **Audit by triggers**: every mutation table carries an `AFTER` trigger that writes the audit row from
   `current_setting('app.actor_fingerprint')`, `app.action_id`, `app.reason_code`, `app.correlation_id`; a transaction
   without them is refused by the trigger. The masked role's reads of raw content are audited at the application layer
   *and* by a trigger on the access-grant table (PRIV-9).
5. **Retention and deletion**: retention is per data class (`DATA_CLASSES_AND_RETENTION.md`); deletion is a worker job
   that removes rows, then **crypto-shreds** the blob's data key, then records a deletion receipt; backups are encrypted
   per-day sets whose restore procedure replays deletion receipts newer than the backup so expired data does not return
   (PRIV-4, AC-6).
6. **Backup**: `pg_dump` of `rwsafe` plus the capture-store key material, encrypted (age, like neXus's platform backup),
   into the host platform backup set under its own retention; the PO names the off-host target (OPEN_QUESTIONS Q-12).
7. **Tuning**: `shared_buffers` 512 MB, `work_mem` 16 MB, connection pool 10 from the control plane and 5 from the
   worker; WAL retention bounded; `log_min_duration_statement` on but statements never log parameter values (bodies are
   not in the database anyway).

## Alternatives considered

- Schema in `ui2-db`: forbidden by the PO; also couples two products' migrations, credentials and backups.
- A shared PostgreSQL instance with two databases: shares memory, WAL and failure domain; rejected.
- Oracle (corporate alternative): no neXus parity, licensing, and HOST-A footprint; not designed for.
- Bodies in PostgreSQL as `bytea`: write amplification and WAL growth on an 80 %-full disk; rejected (Argon risk 3).

## Consequences

- Two PostgreSQL instances on one node: about 1 GiB memory and one more backup set; accepted.
- The data plane cannot be blocked by the database by construction; ArchUnit enforces no JDBC on its classpath.
- Deletion correctness becomes testable (AC-6 "after deletion, nothing remains in backups or the SIEM").

## Evidence and UNVERIFIED facts

- neXus manifests `deploy/ui2/40-database-statefulset.yaml`, `20-secret.yaml`, `10-configmap.yaml`; neXus module deploy
  `audit()` pattern; measured PVC list 2026-10-30.
- UNVERIFIED: none.

## Open questions

OPEN_QUESTIONS Q-5 (retention days per class), Q-12 (off-host backup target).
