package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.jooq.Condition;
import org.jooq.DSLContext;
import org.jooq.Field;
import org.jooq.Record;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

/**
 * The SIEM exporter's reads and its persisted watermark (ADR-002 "SIEM watermarks", ADR-009 C8). Reads return what is
 * already stored: verdict events are metadata only (C1/C2/C6, pseudonymised before persistence) and ledger rows carry a
 * pseudonymous actor; nothing here can return a body.
 *
 * <p><b>Commit-safe order</b> (PR 23 review D-1, migration V7): both exported tables carry {@code tx_id}, the id of the
 * writing transaction. Reads return only rows with {@code tx_id < pg_snapshot_xmin(pg_current_snapshot())}, ordered by
 * ({@code tx_id}, row id), and the watermark is the (tx_id, row id) of the last acknowledged row. Every transaction below
 * a snapshot's xmin has ended, so its rows are all visible to that read (or were aborted); any transaction still running,
 * or not yet holding an id, gets an id at or above that xmin, and later snapshots never have a lower xmin. A row can
 * therefore never become visible behind the watermark. A long transaction holds the xmin back and pauses the export
 * (counted as backlog); it never causes a skip. Each read is one statement, so one snapshot decides both the barrier and
 * the rows.
 */
public final class SiemExportStore {

    private static final Condition VERDICT_VISIBLE = visible(VERDICT_TX_ID);
    private static final Condition AUDIT_VISIBLE = visible(AUDIT_TX_ID);

    private final DSLContext dsl;

    SiemExportStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    /** The position of an acknowledged verdict event. */
    public record VerdictPosition(long txId, UUID eventId) {

        public VerdictPosition {
            Objects.requireNonNull(eventId, "eventId");
        }
    }

    /** The position of an acknowledged ledger row. */
    public record AuditPosition(long txId, long auditId) {
    }

    /** One destination's watermark; a null position means "before the first row" of that stream. */
    public record Watermark(VerdictPosition verdict, AuditPosition audit) {

        public static final Watermark START = new Watermark(null, null);
    }

    /** Where a new destination starts and how many verdict events that start skips (zero from the beginning). */
    public record Start(Watermark watermark, long skippedVerdicts) {
    }

    /** A stored verdict event with its ingestion time and writing transaction (the export order). */
    public record ExportVerdict(StoredVerdictEvent event, Instant ingestedAt, long txId) {

        public VerdictPosition position() {
            return new VerdictPosition(txId, event.eventId());
        }
    }

    /**
     * One audit-ledger row (C7). {@code actorFingerprint} is a {@code USR-} pseudonym or a {@code system:} actor (the
     * trigger refuses anything else); {@code rowKey} is the audited table's key column and may name an account.
     */
    public record LedgerRow(long auditId, long txId, Instant occurredAt, String actorFingerprint, String actionId,
                            String reasonCode, String correlationId, String tableName, String operation,
                            String rowKey) {

        public AuditPosition position() {
            return new AuditPosition(txId, auditId);
        }

        /** Never prints the row key (it may be an account name). */
        @Override
        public String toString() {
            return "LedgerRow[" + auditId + ", " + tableName + ", " + operation + "]";
        }
    }

    public Optional<Watermark> watermark(String destination) {
        Field<String> vtx = text(SW_VERDICT_TX_ID, "verdict_tx");
        Field<String> atx = text(SW_AUDIT_TX_ID, "audit_tx");
        Record r = dsl.select(vtx, SW_VERDICT_EVENT_ID, atx, SW_AUDIT_ID).from(SIEM_WATERMARK)
            .where(SW_DESTINATION.eq(destination)).fetchOne();
        if (r == null) {
            return Optional.empty();
        }
        VerdictPosition v = r.get(vtx) == null ? null
            : new VerdictPosition(Long.parseLong(r.get(vtx)), r.get(SW_VERDICT_EVENT_ID));
        AuditPosition a = r.get(atx) == null ? null : new AuditPosition(Long.parseLong(r.get(atx)), r.get(SW_AUDIT_ID));
        return Optional.of(new Watermark(v, a));
    }

    /** The skip count recorded when the destination's watermark was created. */
    public long skippedAtStart(String destination) {
        Long n = dsl.select(SW_SKIPPED_AT_START).from(SIEM_WATERMARK).where(SW_DESTINATION.eq(destination))
            .fetchOne(SW_SKIPPED_AT_START);
        return n == null ? 0 : n;
    }

    /**
     * A {@code latest} start for verdict events only: the newest visible verdict event and how many visible events lie
     * at or before it (one statement, one snapshot). Ledger rows are never skipped (PO decision Q-SIEM-1).
     */
    public Start latestVerdicts() {
        Field<String> tx = text(VERDICT_TX_ID, "tx");
        Field<Integer> total = DSL.count().over().as("visible_total");
        Record r = dsl.select(tx, EVENT_ID, total).from(VERDICT_EVENT).where(VERDICT_VISIBLE)
            .orderBy(VERDICT_TX_ID.desc(), EVENT_ID.desc()).limit(1).fetchOne();
        if (r == null) {
            return new Start(Watermark.START, 0);
        }
        return new Start(new Watermark(new VerdictPosition(Long.parseLong(r.get(tx)), r.get(EVENT_ID)), null),
            r.get(total));
    }

    /**
     * Creates the destination's watermark once, in a transaction under {@code audit}, so the start (and a skip) is a
     * ledger row that is itself exported. False when the row already existed (nothing changed).
     */
    public boolean createWatermark(String destination, Start start, String startFrom, AuditContext audit) {
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            Watermark w = start.watermark();
            // Plain SQL with typed binds: jOOQ has no xid8 type (the columns are cast from their text form).
            return tx.execute("INSERT INTO siem_watermark (destination, verdict_tx_id, verdict_event_id, audit_tx_id, "
                    + "audit_id, start_from, skipped_at_start) VALUES ({0}, cast({1} as xid8), {2}, cast({3} as xid8), "
                    + "{4}, {5}, {6}) ON CONFLICT (destination) DO NOTHING",
                DSL.val(destination, SQLDataType.CLOB), verdictTx(w), verdictId(w), auditTx(w), auditId(w),
                DSL.val(startFrom, SQLDataType.CLOB), DSL.val(start.skippedVerdicts(), SQLDataType.BIGINT)) == 1;
        });
    }

    /** Moves an existing watermark (system bookkeeping, not ledgered). */
    public void saveWatermark(String destination, Watermark w) {
        int n = dsl.execute("UPDATE siem_watermark SET verdict_tx_id = cast({0} as xid8), verdict_event_id = {1}, "
                + "audit_tx_id = cast({2} as xid8), audit_id = {3}, updated_at = now() WHERE destination = {4}",
            verdictTx(w), verdictId(w), auditTx(w), auditId(w), DSL.val(destination, SQLDataType.CLOB));
        if (n != 1) {
            throw new IllegalStateException("no watermark row for the destination");
        }
    }

    /** Visible verdict events after {@code after} (null: from the first), in export order, at most {@code limit}. */
    public List<ExportVerdict> verdictsAfter(VerdictPosition after, int limit) {
        Field<String> tx = text(VERDICT_TX_ID, "tx");
        List<Field<?>> fields = new ArrayList<>(VerdictQueries.eventFields());
        fields.add(INGESTED_AT);
        fields.add(tx);
        List<Record> rows = dsl.select(fields).from(VERDICT_EVENT).where(VERDICT_VISIBLE.and(after(after)))
            .orderBy(VERDICT_TX_ID, EVENT_ID).limit(limit).fetch();
        Map<UUID, List<FindingCount>> findings = new VerdictQueries(dsl).findings(
            rows.stream().map(r -> r.get(EVENT_ID)).toList());
        return rows.stream().map(r -> new ExportVerdict(
            VerdictQueries.toEvent(r, findings.getOrDefault(r.get(EVENT_ID), List.of())), r.get(INGESTED_AT),
            Long.parseLong(r.get(tx)))).toList();
    }

    /** Visible ledger rows after {@code after} (null: from the first), in export order, at most {@code limit}. */
    public List<LedgerRow> ledgerAfter(AuditPosition after, int limit) {
        Field<String> tx = text(AUDIT_TX_ID, "tx");
        return dsl.select(AUDIT_ID, tx, AUDIT_OCCURRED_AT, AUDIT_ACTOR, AUDIT_ACTION, AUDIT_REASON, AUDIT_CORRELATION,
                AUDIT_TABLE, AUDIT_OPERATION, AUDIT_ROW_KEY)
            .from(AUDIT_EVENT).where(AUDIT_VISIBLE.and(after(after)))
            .orderBy(AUDIT_TX_ID, AUDIT_ID).limit(limit)
            .fetch(r -> new LedgerRow(r.get(AUDIT_ID), Long.parseLong(r.get(tx)), r.get(AUDIT_OCCURRED_AT),
                r.get(AUDIT_ACTOR), r.get(AUDIT_ACTION), r.get(AUDIT_REASON), r.get(AUDIT_CORRELATION),
                r.get(AUDIT_TABLE), r.get(AUDIT_OPERATION), r.get(AUDIT_ROW_KEY)));
    }

    /**
     * Committed rows beyond the watermark, split by the same visibility barrier the reads use (PR 23 confirmation review
     * D-11): {@code visible} can be exported now; {@code held} committed after a transaction that is still open and
     * waits behind the barrier until it ends.
     */
    public record Backlog(long visible, long held) {
    }

    /** The backlog on the health screen and in the metrics; one statement per stream. */
    public Backlog backlog(Watermark w) {
        Field<Integer> v = DSL.count().filterWhere(VERDICT_VISIBLE).as("visible");
        Field<Integer> vh = DSL.count().filterWhere(DSL.not(VERDICT_VISIBLE)).as("held");
        Record verdicts = dsl.select(v, vh).from(VERDICT_EVENT).where(after(w.verdict())).fetchOne();
        Field<Integer> a = DSL.count().filterWhere(AUDIT_VISIBLE).as("visible");
        Field<Integer> ah = DSL.count().filterWhere(DSL.not(AUDIT_VISIBLE)).as("held");
        Record audit = dsl.select(a, ah).from(AUDIT_EVENT).where(after(w.audit())).fetchOne();
        return new Backlog((long) verdicts.get(v) + audit.get(a), (long) verdicts.get(vh) + audit.get(ah));
    }

    private static Condition after(VerdictPosition p) {
        return p == null ? DSL.trueCondition()
            : DSL.condition("({0}, {1}) > (cast({2} as xid8), {3})", VERDICT_TX_ID, EVENT_ID,
                DSL.val(Long.toString(p.txId())), DSL.val(p.eventId(), SQLDataType.UUID));
    }

    private static Condition after(AuditPosition p) {
        return p == null ? DSL.trueCondition()
            : DSL.condition("({0}, {1}) > (cast({2} as xid8), {3})", AUDIT_TX_ID, AUDIT_ID,
                DSL.val(Long.toString(p.txId())), DSL.val(p.auditId(), SQLDataType.BIGINT));
    }

    private static Condition visible(Field<Object> txId) {
        return DSL.condition("{0} < pg_snapshot_xmin(pg_current_snapshot())", txId);
    }

    private static Field<String> text(Field<Object> xid8, String alias) {
        return DSL.field("{0}::text", SQLDataType.CLOB, xid8).as(alias);
    }

    private static Field<String> verdictTx(Watermark w) {
        return DSL.val(w.verdict() == null ? null : Long.toString(w.verdict().txId()), SQLDataType.CLOB);
    }

    private static Field<UUID> verdictId(Watermark w) {
        return DSL.val(w.verdict() == null ? null : w.verdict().eventId(), SQLDataType.UUID);
    }

    private static Field<String> auditTx(Watermark w) {
        return DSL.val(w.audit() == null ? null : Long.toString(w.audit().txId()), SQLDataType.CLOB);
    }

    private static Field<Long> auditId(Watermark w) {
        return DSL.val(w.audit() == null ? null : w.audit().auditId(), SQLDataType.BIGINT);
    }
}
