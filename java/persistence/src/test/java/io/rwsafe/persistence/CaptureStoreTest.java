package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.platform.verdict.Verdict;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.jooq.exception.DataAccessException;
import org.jooq.impl.DSL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * V6 (ADR-009 C3, §4; AGENTS.md 4.13): sealed records only, immutable except the legal hold, every deletion and read
 * ledgered, retention and key shredding through one receipted path, at most 90 days, no truncate.
 */
class CaptureStoreTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private Database db;

    @BeforeEach
    void open() {
        db = Database.migrateAndOpen(TestDatabase.fresh());
    }

    private UUID storedEvent(Instant at) {
        StoredVerdictEvent e = Events.event(at, "claude", Verdict.REDACT, List.of(new FindingCount("TCKN", 1)));
        db.verdictEvents().insert(List.of(e));
        return e.eventId();
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static SealedCapture sealed(UUID id, Instant at, Instant expires, String keyId) {
        return new SealedCapture(id, at, expires, "USR-0123456789", keyId, random(60), random(12), random(48), 32, false,
            "rwmask-v1-slice1", false);
    }

    private long audit(String table, String operation) {
        return db.dsl().fetchCount(Schema.AUDIT_EVENT,
            Schema.AUDIT_TABLE.eq(table).and(Schema.AUDIT_OPERATION.eq(operation)));
    }

    @Test
    void insertIsIdempotentAndARecordIsImmutableExceptItsHold() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        UUID id = storedEvent(now);
        assertTrue(db.captures().insert(sealed(id, now, now.plus(90, ChronoUnit.DAYS), "cap-a")));
        assertFalse(db.captures().insert(sealed(id, now, now.plus(90, ChronoUnit.DAYS), "cap-a")));
        SealedCapture back = db.captures().find(id).orElseThrow();
        assertEquals("cap-a", back.keyId());
        assertEquals(48, back.ciphertext().length);
        assertFalse(back.toString().contains("cap-b"));

        AuditContext ctx = new AuditContext("USR-00000000aa", "capture.hold", "LEGAL_HOLD", null);
        DataAccessException changed = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            ctx.apply(DSL.using(cfg));
            DSL.using(cfg).update(Schema.CAPTURE).set(Schema.CAP_KEY_ID, "cap-b").execute();
        }));
        assertTrue(changed.getMessage().contains("CAPTURE_IMMUTABLE"));
        assertTrue(db.captures().setLegalHold(id, true, ctx));
        assertEquals(1, audit("redacted_capture", "UPDATE"));
        assertThrows(DataAccessException.class, () -> db.dsl().deleteFrom(Schema.CAPTURE).execute(),
            "a delete without an audit context is refused");
        assertThrows(DataAccessException.class, () -> db.dsl().truncate(Schema.CAPTURE).execute());
    }

    @Test
    void retentionIsAtMostNinetyDays() {
        Instant now = Instant.now();
        UUID id = storedEvent(now);
        assertThrows(DataAccessException.class,
            () -> db.captures().insert(sealed(id, now, now.plus(91, ChronoUnit.DAYS), "cap-a")));
    }

    @Test
    void retentionDeletesExpiredRecordsWithAReceiptAndSkipsHolds() {
        Instant past = Instant.now().minus(100, ChronoUnit.DAYS);
        UUID expired = storedEvent(Instant.now());
        UUID held = storedEvent(Instant.now());
        UUID fresh = storedEvent(Instant.now());
        db.captures().insert(sealed(expired, past, past.plus(90, ChronoUnit.DAYS), "cap-a"));
        db.captures().insert(sealed(held, past, past.plus(90, ChronoUnit.DAYS), "cap-a"));
        Instant now = Instant.now();
        db.captures().insert(sealed(fresh, now, now.plus(90, ChronoUnit.DAYS), "cap-a"));
        db.captures().setLegalHold(held, true, new AuditContext("USR-00000000aa", "capture.hold", "LEGAL_HOLD", null));

        assertEquals(1, db.captures().deleteExpired(Instant.now()));
        assertTrue(db.captures().find(expired).isEmpty());
        assertTrue(db.captures().find(held).isPresent(), "a legal hold is never expired");
        assertTrue(db.captures().find(fresh).isPresent());
        assertEquals(1, audit("redacted_capture", "DELETE"));
        assertEquals(1, audit("capture_deletion_receipt", "INSERT"));
        assertEquals("RETENTION_EXPIRED", db.dsl().select(Schema.RCPT_REASON).from(Schema.CAPTURE_RECEIPT).fetchOne(0));
        assertEquals(0, db.captures().deleteExpired(Instant.now()));
        assertEquals(2, db.captures().totals().records());
        assertEquals(96, db.captures().totals().ciphertextBytes());
    }

    @Test
    void aRetiredKeyShredsItsRecords() {
        Instant now = Instant.now();
        UUID old = storedEvent(now);
        UUID current = storedEvent(now);
        db.captures().insert(sealed(old, now, now.plus(90, ChronoUnit.DAYS), "cap-2026a"));
        db.captures().insert(sealed(current, now, now.plus(90, ChronoUnit.DAYS), "cap-2026b"));
        assertEquals(0, db.captures().deleteShredded(Set.of()), "no key mounted is a fault, not a rotation");
        assertEquals(1, db.captures().deleteShredded(Set.of("cap-2026b")));
        assertTrue(db.captures().find(old).isEmpty());
        assertTrue(db.captures().find(current).isPresent());
        assertEquals("KEY_SHREDDED", db.dsl().select(Schema.RCPT_REASON).from(Schema.CAPTURE_RECEIPT).fetchOne(0));
    }

    @Test
    void readsAreLedgeredAndAppendOnly() {
        UUID id = UUID.randomUUID();
        db.captures().recordRead(id, "USR-00000000bb", "INCIDENT_INVESTIGATION", "CASE-0001", "SERVED");
        db.captures().recordRead(id, "USR-00000000bb", "NONE", null, "REFUSED_NO_REASON");
        assertEquals(2, audit("capture_read", "INSERT"));
        assertThrows(DataAccessException.class,
            () -> db.captures().recordRead(id, "USR-00000000bb", "NONE", null, "SERVED"),
            "a served read always carries a reason and a case");
        assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            new AuditContext("USR-00000000bb", "x", "y", null).apply(DSL.using(cfg));
            DSL.using(cfg).deleteFrom(Schema.CAPTURE_READ).execute();
        }));
    }
}
