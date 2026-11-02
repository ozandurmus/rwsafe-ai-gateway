package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import io.rwsafe.persistence.SiemExportStore.LedgerRow;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.jooq.Condition;
import org.jooq.DSLContext;
import org.jooq.Field;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

/**
 * Read-only pages of the audit ledger for Administration -> Records -> Audit log (PO decision Q-47 decision 1.3). The
 * ledger holds who (a pseudonym or a system actor), what (an action id, an audited table and operation, the row's key),
 * when and why (the reason); it has no column that could hold a prompt, a response or any request body. Pages are newest
 * first by ledger id, bounded, and continue with a keyset cursor (the last id of the page).
 */
public final class AuditLedgerQueries {

    /** The largest page the screen may ask for. */
    public static final int MAX_PAGE = 200;
    /** The most distinct action ids offered as a filter. */
    public static final int MAX_ACTIONS = 200;

    private final DSLContext dsl;

    AuditLedgerQueries(DSLContext dsl) {
        this.dsl = dsl;
    }

    /**
     * @param from     inclusive lower bound of {@code occurred_at}
     * @param to       exclusive upper bound of {@code occurred_at}
     * @param actionId an exact action id, or null for every action
     * @param actor    an exact actor ({@code USR-} pseudonym or {@code system:} actor), or null for every actor
     * @param limit    1 to {@link #MAX_PAGE}
     * @param before   only rows with a smaller ledger id (the previous page's cursor), or null for the newest
     */
    public record LedgerFilter(Instant from, Instant to, String actionId, String actor, int limit, Long before) {

        public LedgerFilter {
            Objects.requireNonNull(from, "from");
            Objects.requireNonNull(to, "to");
            if (limit < 1 || limit > MAX_PAGE) {
                throw new IllegalArgumentException("the page size is between 1 and " + MAX_PAGE);
            }
        }
    }

    /** One page; {@code nextBefore} continues it (null: no older row matches). */
    public record LedgerPage(List<LedgerRow> rows, Long nextBefore) {

        public LedgerPage {
            rows = List.copyOf(rows);
        }
    }

    public LedgerPage page(LedgerFilter f) {
        Condition where = AUDIT_OCCURRED_AT.ge(f.from()).and(AUDIT_OCCURRED_AT.lt(f.to()));
        if (f.actionId() != null) {
            where = where.and(AUDIT_ACTION.eq(f.actionId()));
        }
        if (f.actor() != null) {
            where = where.and(AUDIT_ACTOR.eq(f.actor()));
        }
        if (f.before() != null) {
            where = where.and(AUDIT_ID.lt(f.before()));
        }
        Field<String> tx = DSL.field("{0}::text", SQLDataType.CLOB, AUDIT_TX_ID).as("tx");
        // One row more than the page tells whether an older page exists.
        List<LedgerRow> rows = dsl.select(AUDIT_ID, tx, AUDIT_OCCURRED_AT, AUDIT_ACTOR, AUDIT_ACTION, AUDIT_REASON,
                AUDIT_CORRELATION, AUDIT_TABLE, AUDIT_OPERATION, AUDIT_ROW_KEY)
            .from(AUDIT_EVENT).where(where).orderBy(AUDIT_ID.desc()).limit(f.limit() + 1)
            .fetch(r -> new LedgerRow(r.get(AUDIT_ID), Long.parseLong(r.get(tx)), r.get(AUDIT_OCCURRED_AT),
                r.get(AUDIT_ACTOR), r.get(AUDIT_ACTION), r.get(AUDIT_REASON), r.get(AUDIT_CORRELATION),
                r.get(AUDIT_TABLE), r.get(AUDIT_OPERATION), r.get(AUDIT_ROW_KEY)));
        if (rows.size() <= f.limit()) {
            return new LedgerPage(rows, null);
        }
        List<LedgerRow> page = rows.subList(0, f.limit());
        return new LedgerPage(page, page.get(page.size() - 1).auditId());
    }

    /** The action ids the ledger holds, sorted, at most {@link #MAX_ACTIONS} (the screen's action filter). */
    public List<String> actionIds() {
        return dsl.selectDistinct(AUDIT_ACTION).from(AUDIT_EVENT).orderBy(AUDIT_ACTION).limit(MAX_ACTIONS)
            .fetch(AUDIT_ACTION);
    }
}
