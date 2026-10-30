package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import org.jooq.exception.DataAccessException;
import org.jooq.impl.DSL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** C12: acknowledgements are pseudonymous, idempotent per user, version and source, ledgered and never updated. */
class NoticeAcknowledgementStoreTest {

    private static final String USER = "USR-0a1b2c3d4e";
    private static final String OTHER = "USR-9f8e7d6c5b";
    private static final String V1 = "tr-1-0a1b2c3d";
    private static final String V2 = "tr-2-1f2e3d4c";

    private Database db;

    @BeforeEach
    void open() {
        db = Database.migrateAndOpen(TestDatabase.fresh());
        db.noticeAcknowledgements().issue(V1, Instant.parse("2026-09-01T00:00:00Z"));
        db.noticeAcknowledgements().issue(V2, Instant.parse("2026-09-15T00:00:00Z"));
    }

    @Test
    void versionsAreIssuedOnceAndAnUnissuedVersionCannotBeAcknowledged() {
        NoticeAcknowledgementStore store = db.noticeAcknowledgements();
        assertEquals(Instant.parse("2026-09-01T00:00:00Z"), store.issue(V1, Instant.parse("2026-10-30T00:00:00Z")),
            "the first issue time stays");
        assertEquals(java.util.Optional.empty(), store.issuedAt("tr-9-0a1b2c3d"));
        assertThrows(DataAccessException.class,
            () -> store.record(List.of(ack(USER, "tr-9-0a1b2c3d", "banner", "2026-10-01T08:00:00Z"))));
        assertEquals(2, db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_TABLE.eq("notice_version")));
        DataAccessException update = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            new AuditContext("system:test", "notice.change", "TEST", null).apply(tx);
            tx.update(Schema.NOTICE_VERSION).set(Schema.NV_ISSUED_AT, Instant.EPOCH).execute();
        }));
        assertTrue(update.getMessage().contains("AUDIT_APPEND_ONLY"));
    }

    private static NoticeAcknowledgement ack(String user, String version, String source, String at) {
        return new NoticeAcknowledgement(user, version, Instant.parse(at), source, null, "k1");
    }

    @Test
    void recordsAreIdempotentAndQueriedByPseudonym() {
        NoticeAcknowledgementStore store = db.noticeAcknowledgements();
        assertEquals(2, store.record(List.of(ack(USER, V1, "banner", "2026-10-01T08:00:00Z"),
            ack(USER, V1, "directory_attribute", "2026-09-01T00:00:00Z"))));
        assertEquals(0, store.record(List.of(ack(USER, V1, "banner", "2026-10-02T08:00:00Z"))), "the first stays");
        assertEquals(1, store.record(List.of(ack(OTHER, V2, "ide_first_run", "2026-10-03T08:00:00Z"))));

        List<NoticeAcknowledgement> mine = store.forUser(USER);
        assertEquals(2, mine.size());
        assertEquals("banner", mine.get(0).source());
        assertEquals(Instant.parse("2026-10-01T08:00:00Z"), mine.get(0).acknowledgedAt());
        assertNotNull(mine.get(0).recordedAt());
        assertTrue(store.acknowledged(USER, V1));
        assertFalse(store.acknowledged(USER, V2));
        assertFalse(store.acknowledged(OTHER, V1));
        assertEquals(1, store.usersAcknowledged(V1));
        assertEquals(List.of(), store.forUser("USR-0000000000"));
    }

    @Test
    void everyRecordIsLedgeredAndNoneCanBeUpdated() {
        db.noticeAcknowledgements().record(List.of(ack(USER, V1, "banner", "2026-10-01T08:00:00Z")));
        int ledgered = db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_TABLE.eq("notice_acknowledgement")
            .and(Schema.AUDIT_ACTOR.eq("system:notice-intake")).and(Schema.AUDIT_ACTION.eq("notice.acknowledge")));
        assertEquals(1, ledgered);
        DataAccessException update = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            new AuditContext("system:test", "notice.change", "TEST", null).apply(tx);
            tx.update(Schema.NOTICE_ACK).set(Schema.NA_VERSION, V2).execute();
        }));
        assertTrue(update.getMessage().contains("AUDIT_APPEND_ONLY"));
        DataAccessException truncate = assertThrows(DataAccessException.class,
            () -> db.dsl().execute("TRUNCATE notice_acknowledgement"));
        assertTrue(truncate.getMessage().contains("AUDIT_APPEND_ONLY"));
        DataAccessException unaudited = assertThrows(DataAccessException.class,
            () -> db.dsl().deleteFrom(Schema.NOTICE_ACK).execute());
        assertTrue(unaudited.getMessage().contains("AUDIT_CONTEXT_MISSING"), "retention deletes only with a context");
    }

    @Test
    void theSchemaRefusesARawIdentityAnUnknownSourceOrAFreeVersion() {
        NoticeAcknowledgementStore store = db.noticeAcknowledgements();
        for (NoticeAcknowledgement bad : List.of(
            ack("synthetic.person", V1, "banner", "2026-10-01T08:00:00Z"),
            ack(USER, V1, "email", "2026-10-01T08:00:00Z"),
            ack(USER, "latest", "banner", "2026-10-01T08:00:00Z"))) {
            assertThrows(DataAccessException.class, () -> store.record(List.of(bad)));
        }
        assertEquals(List.of(), store.forUser(USER));
    }
}
