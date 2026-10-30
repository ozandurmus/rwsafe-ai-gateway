package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.time.Duration;
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

/**
 * The SIEM exporter's reads and its persisted watermark (ADR-002 "SIEM watermarks", ADR-009 C8). Reads return what is
 * already stored: verdict events are metadata only (C1/C2/C6, pseudonymised before persistence) and ledger rows carry a
 * pseudonymous actor; nothing here can return a body.
 *
 * <p>Commit order is not insertion order: a row becomes visible at its transaction's commit while its
 * {@code ingested_at}/{@code occurred_at} (and its {@code audit_id}) are taken earlier. Every read therefore stops at rows
 * older than a settle window measured on the database's own clock, so a transaction that commits within the window is
 * never overtaken by the watermark. A transaction open longer than the window could be skipped; ingestion and ledger
 * transactions are single short statements (LOCAL_RUN.md "SIEM export" names the residual).
 */
public final class SiemExportStore {

    private final DSLContext dsl;

    SiemExportStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    /** The position of the last acknowledged verdict event, or null before the first one. */
    public record VerdictPosition(Instant ingestedAt, UUID eventId) {

        public VerdictPosition {
            Objects.requireNonNull(ingestedAt, "ingestedAt");
            Objects.requireNonNull(eventId, "eventId");
        }
    }

    /** One destination's watermark: {@code verdict} may be null; {@code auditId} is 0 before the first ledger row. */
    public record Watermark(VerdictPosition verdict, long auditId) {

        public static final Watermark START = new Watermark(null, 0);

        public Watermark {
            if (auditId < 0) {
                throw new IllegalArgumentException("auditId");
            }
        }
    }

    /** A stored verdict event with its ingestion time (the export order). */
    public record ExportVerdict(StoredVerdictEvent event, Instant ingestedAt) {

        public VerdictPosition position() {
            return new VerdictPosition(ingestedAt, event.eventId());
        }
    }

    /**
     * One audit-ledger row (C7). {@code actorFingerprint} is a {@code USR-} pseudonym or a {@code system:} actor (the
     * trigger refuses anything else); {@code rowKey} is the audited table's key column and may name an account.
     */
    public record LedgerRow(long auditId, Instant occurredAt, String actorFingerprint, String actionId,
                            String reasonCode, String correlationId, String tableName, String operation,
                            String rowKey) {

        /** Never prints the row key (it may be an account name). */
        @Override
        public String toString() {
            return "LedgerRow[" + auditId + ", " + tableName + ", " + operation + "]";
        }
    }

    public Optional<Watermark> watermark(String destination) {
        Record r = dsl.select(SW_VERDICT_INGESTED_AT, SW_VERDICT_EVENT_ID, SW_AUDIT_ID).from(SIEM_WATERMARK)
            .where(SW_DESTINATION.eq(destination)).fetchOne();
        if (r == null) {
            return Optional.empty();
        }
        VerdictPosition v = r.get(SW_VERDICT_INGESTED_AT) == null ? null
            : new VerdictPosition(r.get(SW_VERDICT_INGESTED_AT), r.get(SW_VERDICT_EVENT_ID));
        return Optional.of(new Watermark(v, r.get(SW_AUDIT_ID)));
    }

    /** Stores the destination's watermark (insert or replace). */
    public void saveWatermark(String destination, Watermark w) {
        Instant at = w.verdict() == null ? null : w.verdict().ingestedAt();
        UUID id = w.verdict() == null ? null : w.verdict().eventId();
        dsl.insertInto(SIEM_WATERMARK, SW_DESTINATION, SW_VERDICT_INGESTED_AT, SW_VERDICT_EVENT_ID, SW_AUDIT_ID)
            .values(destination, at, id, w.auditId())
            .onConflict(SW_DESTINATION).doUpdate()
            .set(SW_VERDICT_INGESTED_AT, at)
            .set(SW_VERDICT_EVENT_ID, id)
            .set(SW_AUDIT_ID, w.auditId())
            .set(SW_UPDATED_AT, DSL.currentInstant())
            .execute();
    }

    /** The newest settled positions: a destination configured to start at the latest event begins here. */
    public Watermark latest(Duration settle) {
        Record v = dsl.select(INGESTED_AT, EVENT_ID).from(VERDICT_EVENT).where(settled(INGESTED_AT, settle))
            .orderBy(INGESTED_AT.desc(), EVENT_ID.desc()).limit(1).fetchOne();
        Long audit = dsl.select(DSL.max(AUDIT_ID)).from(AUDIT_EVENT).where(settled(AUDIT_OCCURRED_AT, settle))
            .fetchOne(0, Long.class);
        return new Watermark(v == null ? null : new VerdictPosition(v.get(INGESTED_AT), v.get(EVENT_ID)),
            audit == null ? 0 : audit);
    }

    /** Settled verdict events after {@code after} (null: from the first), oldest first, at most {@code limit}. */
    public List<ExportVerdict> verdictsAfter(VerdictPosition after, Duration settle, int limit) {
        Condition c = settled(INGESTED_AT, settle);
        if (after != null) {
            c = c.and(DSL.row(INGESTED_AT, EVENT_ID).gt(after.ingestedAt(), after.eventId()));
        }
        List<Field<?>> fields = new ArrayList<>(VerdictQueries.eventFields());
        fields.add(INGESTED_AT);
        List<Record> rows = dsl.select(fields).from(VERDICT_EVENT).where(c).orderBy(INGESTED_AT, EVENT_ID).limit(limit)
            .fetch();
        Map<UUID, List<FindingCount>> findings = new VerdictQueries(dsl).findings(
            rows.stream().map(r -> r.get(EVENT_ID)).toList());
        return rows.stream().map(r -> new ExportVerdict(
            VerdictQueries.toEvent(r, findings.getOrDefault(r.get(EVENT_ID), List.of())), r.get(INGESTED_AT))).toList();
    }

    /** Settled ledger rows with an id above {@code afterId}, in id order, at most {@code limit}. */
    public List<LedgerRow> ledgerAfter(long afterId, Duration settle, int limit) {
        return dsl.select(AUDIT_ID, AUDIT_OCCURRED_AT, AUDIT_ACTOR, AUDIT_ACTION, AUDIT_REASON, AUDIT_CORRELATION,
                AUDIT_TABLE, AUDIT_OPERATION, AUDIT_ROW_KEY)
            .from(AUDIT_EVENT).where(AUDIT_ID.gt(afterId).and(settled(AUDIT_OCCURRED_AT, settle)))
            .orderBy(AUDIT_ID).limit(limit)
            .fetch(r -> new LedgerRow(r.get(AUDIT_ID), r.get(AUDIT_OCCURRED_AT), r.get(AUDIT_ACTOR), r.get(AUDIT_ACTION),
                r.get(AUDIT_REASON), r.get(AUDIT_CORRELATION), r.get(AUDIT_TABLE), r.get(AUDIT_OPERATION),
                r.get(AUDIT_ROW_KEY)));
    }

    /** How many settled rows lie beyond the watermark (the backlog on the health screen). */
    public long backlog(Watermark w, Duration settle) {
        Condition v = settled(INGESTED_AT, settle);
        if (w.verdict() != null) {
            v = v.and(DSL.row(INGESTED_AT, EVENT_ID).gt(w.verdict().ingestedAt(), w.verdict().eventId()));
        }
        return (long) dsl.fetchCount(VERDICT_EVENT, v)
            + dsl.fetchCount(AUDIT_EVENT, AUDIT_ID.gt(w.auditId()).and(settled(AUDIT_OCCURRED_AT, settle)));
    }

    private static Condition settled(Field<Instant> at, Duration settle) {
        return DSL.condition("{0} < now() - ({1} * interval '1 millisecond')", at, DSL.val(settle.toMillis()));
    }
}
