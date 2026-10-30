package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.jooq.impl.DSL;

/**
 * The C3 capture store (ADR-009 §2, §4; V6): sealed records, the read ledger and the deletion receipts. Retention and
 * key shredding share one deletion path that writes a receipt and is ledgered by the audit trigger; a record on legal
 * hold is skipped by retention. Rows hold ciphertext only.
 */
public final class CaptureStore {

    /** The most records one deletion pass removes (one receipt each, V6 bound). */
    public static final int MAX_DELETE = 1000;
    static final String RETENTION_ACTOR = "system:capture-retention";

    private final DSLContext dsl;

    CaptureStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    /** Stores one sealed record; false when the event already has one (ingestion is idempotent). */
    public boolean insert(SealedCapture c) {
        return dsl.insertInto(CAPTURE, CAP_EVENT_ID, CAP_CAPTURED_AT, CAP_EXPIRES_AT, CAP_USER, CAP_KEY_ID,
                CAP_WRAPPED_KEY, CAP_NONCE, CAP_CIPHERTEXT, CAP_PLAIN_BYTES, CAP_TRUNCATED, CAP_MASK_RULE_SET)
            .values(c.eventId(), c.capturedAt(), c.expiresAt(), c.userPseudonym(), c.keyId(), c.wrappedKey(), c.nonce(),
                c.ciphertext(), c.plainBytes(), c.truncated(), c.maskRuleSet())
            .onConflict(CAP_EVENT_ID).doNothing().execute() == 1;
    }

    public Optional<SealedCapture> find(UUID eventId) {
        return dsl.select(CAP_EVENT_ID, CAP_CAPTURED_AT, CAP_EXPIRES_AT, CAP_USER, CAP_KEY_ID, CAP_WRAPPED_KEY, CAP_NONCE,
                CAP_CIPHERTEXT, CAP_PLAIN_BYTES, CAP_TRUNCATED, CAP_MASK_RULE_SET, CAP_LEGAL_HOLD)
            .from(CAPTURE).where(CAP_EVENT_ID.eq(eventId)).fetchOptional(CaptureStore::sealed);
    }

    /** True when the event has a stored capture (a flag for screens; never the content). */
    public boolean exists(UUID eventId) {
        return dsl.fetchExists(dsl.selectOne().from(CAPTURE).where(CAP_EVENT_ID.eq(eventId)));
    }

    private static SealedCapture sealed(Record r) {
        return new SealedCapture(r.get(CAP_EVENT_ID), r.get(CAP_CAPTURED_AT), r.get(CAP_EXPIRES_AT), r.get(CAP_USER),
            r.get(CAP_KEY_ID), r.get(CAP_WRAPPED_KEY), r.get(CAP_NONCE), r.get(CAP_CIPHERTEXT), r.get(CAP_PLAIN_BYTES),
            r.get(CAP_TRUNCATED), r.get(CAP_MASK_RULE_SET), r.get(CAP_LEGAL_HOLD));
    }

    /**
     * Ledgers one read request (AGENTS.md 4.13) under the reader's pseudonym, in its own transaction, before any content
     * is opened: when this fails nothing is served.
     *
     * @param reasonCode one of the V6 reason codes, {@code NONE} for a refused request without one
     * @param outcome    {@code SERVED}, {@code REFUSED_NO_REASON}, {@code NOT_FOUND} or {@code KEY_UNAVAILABLE}
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

    /** Retention (Q-5: 90 days): deletes up to {@link #MAX_DELETE} expired records not on hold; returns how many. */
    public int deleteExpired(Instant now) {
        return delete("RETENTION_EXPIRED", "capture.retention_expired",
            CAP_EXPIRES_AT.le(now).and(CAP_LEGAL_HOLD.isFalse()));
    }

    /**
     * Crypto-shredding by key rotation: the records under a capture key that is no longer mounted cannot be opened by
     * anyone; their rows are deleted (up to {@link #MAX_DELETE}) with a receipt per key. A held record is not deleted,
     * though it stays unreadable until its key returns.
     */
    public int deleteShredded(Set<String> liveKeyIds) {
        if (liveKeyIds.isEmpty()) {
            // No key mounted at all is a configuration fault, not a rotation: nothing is deleted on that evidence.
            return 0;
        }
        return delete("KEY_SHREDDED", "capture.key_shredded",
            CAP_KEY_ID.notIn(liveKeyIds).and(CAP_LEGAL_HOLD.isFalse()));
    }

    private int delete(String reason, String action, org.jooq.Condition which) {
        AuditContext audit = new AuditContext(RETENTION_ACTOR, action, reason, UUID.randomUUID().toString());
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            List<Record> rows = new ArrayList<>(tx.select(CAP_EVENT_ID, CAP_KEY_ID).from(CAPTURE).where(which)
                .orderBy(CAP_EXPIRES_AT).limit(MAX_DELETE).forUpdate().fetch());
            if (rows.isEmpty()) {
                return 0;
            }
            Map<String, List<UUID>> byKey = new LinkedHashMap<>();
            List<UUID> ids = new ArrayList<>(rows.size());
            for (Record r : rows) {
                ids.add(r.get(CAP_EVENT_ID));
                byKey.computeIfAbsent(r.get(CAP_KEY_ID), k -> new ArrayList<>()).add(r.get(CAP_EVENT_ID));
            }
            int deleted = tx.deleteFrom(CAPTURE).where(CAP_EVENT_ID.in(ids)).execute();
            for (Map.Entry<String, List<UUID>> e : byKey.entrySet()) {
                tx.insertInto(CAPTURE_RECEIPT, RCPT_REASON, RCPT_KEY_ID, RCPT_EVENT_IDS)
                    .values(reason, e.getKey(), e.getValue().toArray(UUID[]::new)).execute();
            }
            return deleted;
        });
    }

    /** Stored records and their ciphertext bytes (Health). */
    public Totals totals() {
        Record r = dsl.select(DSL.count(), DSL.coalesce(DSL.sum(DSL.field("octet_length({0})", Long.class,
                CAP_CIPHERTEXT)), DSL.inline(java.math.BigDecimal.ZERO)))
            .from(CAPTURE).fetchOne();
        return new Totals(r.get(0, Long.class), r.get(1, Long.class));
    }

    public record Totals(long records, long ciphertextBytes) {
    }
}
