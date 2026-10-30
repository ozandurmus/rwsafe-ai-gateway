package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.jooq.DSLContext;
import org.jooq.InsertValuesStep4;
import org.jooq.Record;
import org.jooq.impl.DSL;

/** Writes verdict events. Ingestion is idempotent on {@code eventId}: a retried batch inserts nothing twice. */
public final class VerdictEventStore {

    private final DSLContext dsl;

    VerdictEventStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    /** Inserts the batch in one transaction and returns how many events were new. */
    public int insert(List<StoredVerdictEvent> events) {
        if (events.isEmpty()) {
            return 0;
        }
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            var insert = tx.insertInto(VERDICT_EVENT, EVENT_ID, RECEIVED_AT, SERVICE, PLATFORM, SURFACE, STEP, VERDICT,
                REASON, BODY_BYTES, DECISION_MICROS, USER_PSEUDONYM, CLIENT_SUBNET, TRANSPORT, SNAPSHOT_VERSION,
                CORRELATION_ID, PSEUDONYM_KEY_ID);
            for (StoredVerdictEvent e : events) {
                insert = insert.values(DSL.row(e.eventId(), e.receivedAt(), e.service(), e.platform(), e.surface(),
                    e.step(), e.verdict().name(), e.reason(), e.bodyBytes(), e.decisionMicros(), e.userPseudonym(),
                    e.clientSubnet(), e.transport(), e.snapshotVersion(), e.correlationId(), e.pseudonymKeyId()));
            }
            Set<UUID> inserted = new HashSet<>(insert.onConflict(EVENT_ID).doNothing().returning(EVENT_ID).fetch(EVENT_ID));
            InsertValuesStep4<Record, UUID, String, Integer, String> findings = null;
            for (StoredVerdictEvent e : events) {
                if (!inserted.contains(e.eventId())) {
                    continue;
                }
                for (FindingCount f : e.findings()) {
                    if (findings == null) {
                        findings = tx.insertInto(VERDICT_FINDING, FINDING_EVENT_ID, DATA_CLASS, HIT_COUNT, DIGEST);
                    }
                    findings = findings.values(e.eventId(), f.dataClass(), f.count(), null);
                }
            }
            if (findings != null) {
                findings.execute();
            }
            return inserted.size();
        });
    }
}
