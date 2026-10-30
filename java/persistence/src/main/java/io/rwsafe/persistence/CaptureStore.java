package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.jooq.Condition;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.jooq.impl.DSL;

/**
 * The C3 capture store's metadata (ADR-009 §2-§4; V8): records, their manifests (record -> ordered chunks), the chunks'
 * keyed content addresses, wrapped data keys and reference counts, the byte counter, the read ledger, deletion receipts
 * and key events. The chunk bytes are files on the capture volume, written and read by the control plane; this module
 * holds no plaintext, no ciphertext and no key. Retention, the byte cap and emergency shredding share one deletion path
 * that writes a receipt and is ledgered by the audit trigger; a record on legal hold is never deleted by it.
 */
public final class CaptureStore {

    /** The most records one deletion pass removes (one receipt each, V8 bound). */
    public static final int MAX_DELETE = 1000;
    static final String RETENTION_ACTOR = "system:capture-retention";
    static final String KEYS_ACTOR = "system:capture-keys";

    private final DSLContext dsl;

    CaptureStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    /** One record's metadata; {@code wrappedKey} wraps the record key whose HMAC is {@code manifestMac}. */
    public record CaptureRecord(UUID eventId, Instant capturedAt, Instant expiresAt, String userPseudonym, String keyId,
                                byte[] wrappedKey, byte[] manifestMac, int plainBytes, boolean truncated,
                                String maskRuleSet, boolean legalHold) {

        @Override
        public String toString() {
            return "CaptureRecord[" + eventId + ", key " + keyId + ", " + plainBytes + " bytes]";
        }
    }

    /**
     * One chunk of a record to insert, in order. {@code wrappedKey} is null for a chunk the caller found stored already
     * (it is then referenced, never written again).
     */
    public record ChunkPlan(String address, UUID chunkId, String keyId, byte[] wrappedKey, int storedBytes) {

        @Override
        public String toString() {
            return "ChunkPlan[" + chunkId + "]";
        }
    }

    /** A stored chunk as a manifest names it. */
    public record StoredChunk(UUID chunkId, String address, String keyId, byte[] wrappedKey, int storedBytes) {

        @Override
        public String toString() {
            return "StoredChunk[" + chunkId + ", key " + keyId + "]";
        }
    }

    /** {@code stored} false: the event already had a record. {@code newChunks}: the plans whose row this insert created. */
    public record Inserted(boolean stored, Set<UUID> newChunks) {
    }

    /** What one deletion pass removed: records, and the chunks left without a reference (their files go next). */
    public record Deleted(int records, List<UUID> chunkIds) {

        public static final Deleted NONE = new Deleted(0, List.of());
    }

    /** A new wrapping of a record key or a chunk data key under {@code toKeyId}. */
    public record Rewrap(UUID id, String fromKeyId, String toKeyId, byte[] wrappedKey) {
    }

    /** The chunks of {@code addresses} stored already, address to chunk id. */
    public Map<String, UUID> existingChunks(Collection<String> addresses) {
        if (addresses.isEmpty()) {
            return Map.of();
        }
        Map<String, UUID> out = new HashMap<>();
        dsl.select(CH_ADDRESS, CH_ID).from(CAPTURE_CHUNK).where(CH_ADDRESS.in(addresses))
            .forEach(r -> out.put(r.get(CH_ADDRESS), r.get(CH_ID)));
        return out;
    }

    /**
     * Stores a record and its manifest in one transaction. A plan with a wrapped key inserts its chunk unless a concurrent
     * insert stored the same address first (then that chunk is referenced); {@code onNewChunk} runs inside the
     * transaction for every chunk row this insert created (the caller moves its file into place; a failure there rolls
     * everything back). A plan without a wrapped key must still be stored: it is locked and referenced.
     */
    public Inserted insert(CaptureRecord r, List<ChunkPlan> chunks, Consumer<UUID> onNewChunk) {
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            int rows = tx.insertInto(CAPTURE, CAP_EVENT_ID, CAP_CAPTURED_AT, CAP_EXPIRES_AT, CAP_USER, CAP_KEY_ID,
                    CAP_WRAPPED_KEY, CAP_MAC, CAP_PLAIN_BYTES, CAP_TRUNCATED, CAP_MASK_RULE_SET)
                .values(r.eventId(), r.capturedAt(), r.expiresAt(), r.userPseudonym(), r.keyId(), r.wrappedKey(),
                    r.manifestMac(), r.plainBytes(), r.truncated(), r.maskRuleSet())
                .onConflict(CAP_EVENT_ID).doNothing().execute();
            if (rows == 0) {
                return new Inserted(false, Set.of());
            }
            Map<String, UUID> ids = new HashMap<>();
            Set<UUID> created = new LinkedHashSet<>();
            for (ChunkPlan c : chunks) {
                if (ids.containsKey(c.address())) {
                    continue;
                }
                UUID id = null;
                if (c.wrappedKey() != null) {
                    id = tx.insertInto(CAPTURE_CHUNK, CH_ID, CH_ADDRESS, CH_KEY_ID, CH_WRAPPED_KEY, CH_STORED_BYTES)
                        .values(c.chunkId(), c.address(), c.keyId(), c.wrappedKey(), c.storedBytes())
                        .onConflict(CH_ADDRESS).doNothing().returning(CH_ID).fetchOptional(CH_ID).orElse(null);
                    if (id != null) {
                        onNewChunk.accept(id);
                        created.add(id);
                    }
                }
                if (id == null) {
                    // Locked so a concurrent deletion of an unreferenced chunk waits and then sees the new reference.
                    id = tx.select(CH_ID).from(CAPTURE_CHUNK).where(CH_ADDRESS.eq(c.address())).forUpdate()
                        .fetchOptional(CH_ID)
                        .orElseThrow(() -> new IllegalStateException("a referenced chunk is no longer stored"));
                }
                ids.put(c.address(), id);
            }
            var manifest = tx.insertInto(CAPTURE_MANIFEST, MF_EVENT_ID, MF_SEQ, MF_CHUNK_ID);
            for (int i = 0; i < chunks.size(); i++) {
                manifest = manifest.values(r.eventId(), (short) i, ids.get(chunks.get(i).address()));
            }
            manifest.execute();
            return new Inserted(true, created);
        });
    }

    /** The record of an event, unless it has expired and carries no hold (PR 25 review D-01: never served then). */
    public Optional<CaptureRecord> findLive(UUID eventId, Instant now) {
        return dsl.select(CAP_EVENT_ID, CAP_CAPTURED_AT, CAP_EXPIRES_AT, CAP_USER, CAP_KEY_ID, CAP_WRAPPED_KEY, CAP_MAC,
                CAP_PLAIN_BYTES, CAP_TRUNCATED, CAP_MASK_RULE_SET, CAP_LEGAL_HOLD)
            .from(CAPTURE)
            .where(CAP_EVENT_ID.eq(eventId).and(CAP_EXPIRES_AT.gt(now).or(CAP_LEGAL_HOLD.isTrue())))
            .fetchOptional(CaptureStore::record);
    }

    private static CaptureRecord record(Record r) {
        return new CaptureRecord(r.get(CAP_EVENT_ID), r.get(CAP_CAPTURED_AT), r.get(CAP_EXPIRES_AT), r.get(CAP_USER),
            r.get(CAP_KEY_ID), r.get(CAP_WRAPPED_KEY), r.get(CAP_MAC), r.get(CAP_PLAIN_BYTES), r.get(CAP_TRUNCATED),
            r.get(CAP_MASK_RULE_SET), r.get(CAP_LEGAL_HOLD));
    }

    /** The record's chunks in order. */
    public List<StoredChunk> manifest(UUID eventId) {
        return dsl.select(CH_ID, CH_ADDRESS, CH_KEY_ID, CH_WRAPPED_KEY, CH_STORED_BYTES)
            .from(CAPTURE_MANIFEST).join(CAPTURE_CHUNK).on(CH_ID.eq(MF_CHUNK_ID))
            .where(MF_EVENT_ID.eq(eventId)).orderBy(MF_SEQ)
            .fetch(r -> new StoredChunk(r.get(CH_ID), r.get(CH_ADDRESS), r.get(CH_KEY_ID), r.get(CH_WRAPPED_KEY),
                r.get(CH_STORED_BYTES)));
    }

    /** The chunk ids among {@code ids} that have a row (the file sweep keeps exactly those). */
    public Set<UUID> knownChunks(Collection<UUID> ids) {
        if (ids.isEmpty()) {
            return Set.of();
        }
        return new LinkedHashSet<>(dsl.select(CH_ID).from(CAPTURE_CHUNK).where(CH_ID.in(ids)).fetch(CH_ID));
    }

    /**
     * Ledgers one read request (AGENTS.md 4.13) under the reader's pseudonym, in its own transaction; when this fails
     * nothing is served.
     *
     * @param reasonCode one of the V8 reason codes, {@code NONE} for a request without one
     * @param outcome    one of the V8 outcomes; {@code SERVED} only after the record opened
     */
    public long recordRead(UUID eventId, String actorFingerprint, String reasonCode, String caseId, String outcome) {
        AuditContext audit = new AuditContext(actorFingerprint, "capture.read", reasonCode,
            UUID.randomUUID().toString());
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            return tx.insertInto(CAPTURE_READ, CR_EVENT_ID, CR_ACTOR, CR_REASON, CR_CASE, CR_OUTCOME)
                .values(eventId, actorFingerprint, reasonCode, caseId, outcome).returning(CR_ID).fetchOne(CR_ID);
        });
    }

    /** Places or lifts a legal hold (ADR-009 §4), ledgered under {@code audit}. */
    public boolean setLegalHold(UUID eventId, boolean hold, AuditContext audit) {
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            return tx.update(CAPTURE).set(CAP_LEGAL_HOLD, hold).where(CAP_EVENT_ID.eq(eventId)).execute() == 1;
        });
    }

    /** The store's byte counter (ADR-009 §3): the bytes of every chunk on disk. */
    public long usage() {
        Long n = dsl.select(USAGE_BYTES).from(CAPTURE_USAGE).fetchOne(USAGE_BYTES);
        return n == null ? 0 : n;
    }

    /** Retention (Q-5: 90 days): deletes up to {@link #MAX_DELETE} expired records not on hold. */
    public Deleted deleteExpired(Instant now) {
        return delete("RETENTION_EXPIRED", null, "capture.retention_expired",
            CAP_EXPIRES_AT.le(now).and(CAP_LEGAL_HOLD.isFalse()), CAP_EXPIRES_AT, MAX_DELETE, false);
    }

    /** The byte cap (ADR-009 §3, MAX_STORE_BYTES): deletes the {@code n} oldest records not on hold. */
    public Deleted evictOldest(int n) {
        return delete("STORE_CAP_EVICTED", null, "capture.store_cap_evicted", CAP_LEGAL_HOLD.isFalse(), CAP_CAPTURED_AT,
            Math.min(n, MAX_DELETE), false);
    }

    /**
     * Emergency crypto-shredding (PR 25 Q-3): the records sealed under {@code keyId}, or referencing a chunk under it, are
     * deleted (up to {@link #MAX_DELETE}) with a receipt and an {@code EMERGENCY_SHRED} key event. The caller runs it only
     * for a key the Secret lists as shredded and no longer mounts. A held record stays (unreadable) and is reported.
     */
    public Deleted deleteShredded(String keyId) {
        Condition underKey = CAP_KEY_ID.eq(keyId).or(DSL.exists(DSL.selectOne().from(CAPTURE_MANIFEST)
            .join(CAPTURE_CHUNK).on(CH_ID.eq(MF_CHUNK_ID))
            .where(MF_EVENT_ID.eq(CAP_EVENT_ID).and(CH_KEY_ID.eq(keyId)))));
        return delete("KEY_SHREDDED", keyId, "capture.key_shredded", underKey.and(CAP_LEGAL_HOLD.isFalse()),
            CAP_CAPTURED_AT, MAX_DELETE, true);
    }

    private Deleted delete(String reason, String keyId, String action, Condition which,
                           org.jooq.Field<Instant> order, int limit, boolean keyEvent) {
        AuditContext audit = new AuditContext(keyEvent ? KEYS_ACTOR : RETENTION_ACTOR, action, reason,
            UUID.randomUUID().toString());
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            List<UUID> ids = tx.select(CAP_EVENT_ID).from(CAPTURE).where(which).orderBy(order).limit(limit)
                .forUpdate().fetch(CAP_EVENT_ID);
            int records = ids.isEmpty() ? 0 : tx.deleteFrom(CAPTURE).where(CAP_EVENT_ID.in(ids)).execute();
            // The manifest rows went with the records; their triggers released the references.
            List<UUID> chunks = tx.deleteFrom(CAPTURE_CHUNK).where(CH_REF_COUNT.eq(0)).returning(CH_ID).fetch(CH_ID);
            if (records == 0 && chunks.isEmpty()) {
                return Deleted.NONE;
            }
            tx.insertInto(CAPTURE_RECEIPT, RCPT_REASON, RCPT_KEY_ID, RCPT_EVENT_IDS, RCPT_CHUNKS)
                .values(reason, keyId, ids.toArray(UUID[]::new), chunks.size()).execute();
            if (keyEvent) {
                tx.insertInto(CAPTURE_KEY_EVENT, KE_OPERATION, KE_FROM, KE_TO, KE_RECORDS, KE_CHUNKS)
                    .values("EMERGENCY_SHRED", keyId, null, records, chunks.size()).execute();
            }
            return new Deleted(records, chunks);
        });
    }

    /** Records sealed under another key than {@code activeKeyId} that are still within retention or on hold. */
    public List<CaptureRecord> recordsToRewrap(String activeKeyId, Instant now, int limit) {
        return dsl.select(CAP_EVENT_ID, CAP_CAPTURED_AT, CAP_EXPIRES_AT, CAP_USER, CAP_KEY_ID, CAP_WRAPPED_KEY, CAP_MAC,
                CAP_PLAIN_BYTES, CAP_TRUNCATED, CAP_MASK_RULE_SET, CAP_LEGAL_HOLD)
            .from(CAPTURE)
            .where(CAP_KEY_ID.ne(activeKeyId).and(CAP_EXPIRES_AT.gt(now).or(CAP_LEGAL_HOLD.isTrue())))
            .orderBy(CAP_EVENT_ID).limit(limit).fetch(CaptureStore::record);
    }

    /** Referenced chunks wrapped under another key than {@code activeKeyId}. */
    public List<StoredChunk> chunksToRewrap(String activeKeyId, int limit) {
        return dsl.select(CH_ID, CH_ADDRESS, CH_KEY_ID, CH_WRAPPED_KEY, CH_STORED_BYTES).from(CAPTURE_CHUNK)
            .where(CH_KEY_ID.ne(activeKeyId).and(CH_REF_COUNT.gt(0))).orderBy(CH_ID).limit(limit)
            .fetch(r -> new StoredChunk(r.get(CH_ID), r.get(CH_ADDRESS), r.get(CH_KEY_ID), r.get(CH_WRAPPED_KEY),
                r.get(CH_STORED_BYTES)));
    }

    /**
     * A planned rotation's re-wrap (PR 25 Q-3), in one ledgered transaction: each new wrapping replaces the old one only
     * while the row is still under {@code fromKeyId}; one {@code REWRAP} key event per previous key. Returns the rows
     * updated.
     */
    public int applyRewrap(List<Rewrap> records, List<Rewrap> chunks) {
        if (records.isEmpty() && chunks.isEmpty()) {
            return 0;
        }
        AuditContext audit = new AuditContext(KEYS_ACTOR, "capture.rewrap", "KEY_ROTATION", UUID.randomUUID().toString());
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            Map<String, int[]> perKey = new LinkedHashMap<>();
            String to = null;
            int n = 0;
            for (Rewrap w : records) {
                int u = tx.update(CAPTURE).set(CAP_KEY_ID, w.toKeyId()).set(CAP_WRAPPED_KEY, w.wrappedKey())
                    .where(CAP_EVENT_ID.eq(w.id()).and(CAP_KEY_ID.eq(w.fromKeyId()))).execute();
                perKey.computeIfAbsent(w.fromKeyId(), k -> new int[2])[0] += u;
                n += u;
                to = w.toKeyId();
            }
            for (Rewrap w : chunks) {
                int u = tx.update(CAPTURE_CHUNK).set(CH_KEY_ID, w.toKeyId()).set(CH_WRAPPED_KEY, w.wrappedKey())
                    .where(CH_ID.eq(w.id()).and(CH_KEY_ID.eq(w.fromKeyId()))).execute();
                perKey.computeIfAbsent(w.fromKeyId(), k -> new int[2])[1] += u;
                n += u;
                to = w.toKeyId();
            }
            for (Map.Entry<String, int[]> e : perKey.entrySet()) {
                if (e.getValue()[0] + e.getValue()[1] > 0) {
                    tx.insertInto(CAPTURE_KEY_EVENT, KE_OPERATION, KE_FROM, KE_TO, KE_RECORDS, KE_CHUNKS)
                        .values("REWRAP", e.getKey(), to, e.getValue()[0], e.getValue()[1]).execute();
                }
            }
            return n;
        });
    }

    /** Counts for the Health screen. */
    public Totals totals(String activeKeyId) {
        String active = activeKeyId == null ? "" : activeKeyId;
        long records = dsl.fetchCount(CAPTURE);
        long chunks = dsl.fetchCount(CAPTURE_CHUNK);
        long held = dsl.fetchCount(CAPTURE, CAP_LEGAL_HOLD.isTrue());
        long recordsElsewhere = dsl.fetchCount(CAPTURE, CAP_KEY_ID.ne(active));
        long chunksElsewhere = dsl.fetchCount(CAPTURE_CHUNK, CH_KEY_ID.ne(active));
        return new Totals(records, chunks, usage(), held, recordsElsewhere, chunksElsewhere);
    }

    /** {@code *UnderOtherKeys}: still wrapped under a key other than the active one (a rotation not yet re-wrapped). */
    public record Totals(long records, long chunks, long storedBytes, long heldRecords, long recordsUnderOtherKeys,
                         long chunksUnderOtherKeys) {
    }

    /** The key ids that still wrap a record or a chunk. */
    public Set<String> keysInUse() {
        Set<String> out = new LinkedHashSet<>(dsl.selectDistinct(CAP_KEY_ID).from(CAPTURE).fetch(CAP_KEY_ID));
        out.addAll(dsl.selectDistinct(CH_KEY_ID).from(CAPTURE_CHUNK).fetch(CH_KEY_ID));
        return out;
    }
}
