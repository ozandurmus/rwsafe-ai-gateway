package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.util.List;
import java.util.UUID;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;

/**
 * Notice acknowledgements (ADR-009 C12). Recording is idempotent per user, version and source (the first record stays);
 * every insert is ledgered by the audit trigger under the intake's system actor.
 */
public final class NoticeAcknowledgementStore {

    /** At most this many records of one user are returned (newest first). */
    public static final int MAX_PER_USER = 100;

    private final DSLContext dsl;

    NoticeAcknowledgementStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    /** Inserts the batch in one transaction and returns how many records were new. */
    public int record(List<NoticeAcknowledgement> batch) {
        if (batch.isEmpty()) {
            return 0;
        }
        AuditContext audit = new AuditContext("system:notice-intake", "notice.acknowledge", "NOTICE_ACKNOWLEDGEMENT",
            UUID.randomUUID().toString());
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            var insert = tx.insertInto(NOTICE_ACK, NA_USER, NA_VERSION, NA_ACKNOWLEDGED_AT, NA_SOURCE, NA_KEY_ID);
            for (NoticeAcknowledgement a : batch) {
                insert = insert.values(a.userPseudonym(), a.noticeVersion(), a.acknowledgedAt(), a.source(),
                    a.pseudonymKeyId());
            }
            return insert.onConflict(NA_USER, NA_VERSION, NA_SOURCE).doNothing().execute();
        });
    }

    /** The records of one pseudonym, newest acknowledgement first. */
    public List<NoticeAcknowledgement> forUser(String userPseudonym) {
        return dsl.select(NA_USER, NA_VERSION, NA_ACKNOWLEDGED_AT, NA_SOURCE, NA_RECORDED_AT, NA_KEY_ID)
            .from(NOTICE_ACK)
            .where(NA_USER.eq(userPseudonym))
            .orderBy(NA_ACKNOWLEDGED_AT.desc(), NA_ID.desc())
            .limit(MAX_PER_USER)
            .fetch(r -> new NoticeAcknowledgement(r.get(NA_USER), r.get(NA_VERSION), r.get(NA_ACKNOWLEDGED_AT),
                r.get(NA_SOURCE), r.get(NA_RECORDED_AT), r.get(NA_KEY_ID)));
    }

    /** True when the pseudonym has a record of {@code noticeVersion} from any source (SR-PRIV-10). */
    public boolean acknowledged(String userPseudonym, String noticeVersion) {
        return dsl.fetchExists(dsl.selectOne().from(NOTICE_ACK)
            .where(NA_USER.eq(userPseudonym).and(NA_VERSION.eq(noticeVersion))));
    }

    /** How many distinct users acknowledged {@code noticeVersion} (a count, never a list of people). */
    public long usersAcknowledged(String noticeVersion) {
        Long n = dsl.select(DSL.countDistinct(NA_USER)).from(NOTICE_ACK).where(NA_VERSION.eq(noticeVersion))
            .fetchOne(0, Long.class);
        return n == null ? 0 : n;
    }
}
