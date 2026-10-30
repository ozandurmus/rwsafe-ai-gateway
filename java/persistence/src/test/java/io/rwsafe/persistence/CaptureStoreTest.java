package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.persistence.CaptureStore.CaptureRecord;
import io.rwsafe.persistence.CaptureStore.ChunkPlan;
import io.rwsafe.platform.verdict.Verdict;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.jooq.exception.DataAccessException;
import org.jooq.impl.DSL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * V8 (ADR-009 C3, §2-§4; AGENTS.md 4.13): metadata only, chunks content-addressed and stored once with exact reference
 * counts and a byte counter, records immutable except hold and wrapping, every deletion receipted and ledgered, expired
 * records never found, retention at most 90 days, the byte cap evicts oldest first, re-wrap and emergency shredding are
 * key events.
 */
class CaptureStoreTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AuditContext HOLD = new AuditContext("USR-00000000aa", "capture.hold", "LEGAL_HOLD", null);
    private Database db;

    @BeforeEach
    void open() {
        db = Database.migrateAndOpen(TestDatabase.fresh());
    }

    private UUID storedEvent() {
        StoredVerdictEvent e = Events.event(Instant.now(), "claude", Verdict.REDACT, List.of(new FindingCount("TCKN", 1)));
        db.verdictEvents().insert(List.of(e));
        return e.eventId();
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static String address() {
        return HexFormat.of().formatHex(random(32));
    }

    private static CaptureRecord record(UUID id, Instant at, Instant expires, String keyId) {
        return new CaptureRecord(id, at, expires, "USR-0123456789", keyId, random(60), random(32), 100, false,
            "rwmask-v1-slice1", false);
    }

    private static ChunkPlan chunk(String address, int bytes, String keyId) {
        return new ChunkPlan(address, UUID.randomUUID(), keyId, random(60), bytes);
    }

    private UUID stored(Instant at, Instant expires, String keyId, ChunkPlan... chunks) {
        UUID id = storedEvent();
        assertTrue(db.captures().insert(record(id, at, expires, keyId), List.of(chunks), c -> { }).stored());
        return id;
    }

    private long audit(String table, String operation) {
        return db.dsl().fetchCount(Schema.AUDIT_EVENT,
            Schema.AUDIT_TABLE.eq(table).and(Schema.AUDIT_OPERATION.eq(operation)));
    }

    private int refs(String address) {
        return db.dsl().select(Schema.CH_REF_COUNT).from(Schema.CAPTURE_CHUNK).where(Schema.CH_ADDRESS.eq(address))
            .fetchOne(Schema.CH_REF_COUNT);
    }

    @Test
    void aRepeatedChunkIsStoredOnceAndCounted() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        String shared = address();
        List<UUID> created = new ArrayList<>();
        UUID a = storedEvent();
        db.captures().insert(record(a, now, now.plus(90, ChronoUnit.DAYS), "cap-a"),
            List.of(chunk(shared, 1000, "cap-a"), chunk(address(), 500, "cap-a")), created::add);
        assertEquals(2, created.size());
        UUID b = storedEvent();
        ChunkPlan known = new ChunkPlan(shared, UUID.randomUUID(), "cap-a", null, 1000);
        var second = db.captures().insert(record(b, now, now.plus(90, ChronoUnit.DAYS), "cap-a"),
            List.of(known, chunk(address(), 300, "cap-a")), created::add);
        assertEquals(1, second.newChunks().size(), "the shared chunk is referenced, not written again");
        assertEquals(2, refs(shared));
        assertEquals(1800, db.captures().usage(), "the byte counter holds every chunk once");
        assertEquals(2, db.captures().manifest(b).size());
        assertEquals(shared, db.captures().manifest(b).get(0).address());
        assertFalse(db.captures().insert(record(a, now, now.plus(90, ChronoUnit.DAYS), "cap-a"), List.of(), c -> { })
            .stored(), "idempotent per event");
        assertEquals(1, db.captures().existingChunks(List.of(shared, address())).size());
    }

    @Test
    void aRecordIsImmutableExceptItsHoldAndWrapping() {
        Instant now = Instant.now();
        UUID id = stored(now, now.plus(90, ChronoUnit.DAYS), "cap-a", chunk(address(), 100, "cap-a"));
        DataAccessException changed = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            HOLD.apply(DSL.using(cfg));
            DSL.using(cfg).update(Schema.CAPTURE).set(Schema.CAP_EXPIRES_AT, now.plus(80, ChronoUnit.DAYS)).execute();
        }));
        assertTrue(changed.getMessage().contains("CAPTURE_IMMUTABLE"));
        assertTrue(db.captures().setLegalHold(id, true, HOLD));
        assertEquals(1, audit("capture_record", "UPDATE"));
        assertThrows(DataAccessException.class, () -> db.dsl().deleteFrom(Schema.CAPTURE).execute(),
            "a delete without an audit context is refused");
        assertThrows(DataAccessException.class, () -> db.dsl().truncate(Schema.CAPTURE).execute());
        assertThrows(DataAccessException.class, () -> db.dsl().truncate(Schema.CAPTURE_CHUNK).execute());
        UUID other = storedEvent();
        assertThrows(DataAccessException.class, () -> db.captures().insert(
            record(other, now, now.plus(91, ChronoUnit.DAYS), "cap-a"), List.of(), c -> { }), "at most 90 days");
    }

    @Test
    void expiredRecordsAreNeverFoundAndRetentionDeletesThemWithAReceipt() {
        Instant past = Instant.now().minus(100, ChronoUnit.DAYS);
        Instant now = Instant.now();
        String shared = address();
        String alone = address();
        UUID expired = stored(past, past.plus(90, ChronoUnit.DAYS), "cap-a", chunk(shared, 400, "cap-a"),
            chunk(alone, 200, "cap-a"));
        UUID held = stored(past, past.plus(90, ChronoUnit.DAYS), "cap-a", chunk(address(), 100, "cap-a"));
        UUID fresh = stored(now, now.plus(90, ChronoUnit.DAYS), "cap-a",
            new ChunkPlan(shared, UUID.randomUUID(), "cap-a", null, 400));
        db.captures().setLegalHold(held, true, HOLD);
        assertTrue(db.captures().findLive(expired, now).isEmpty(), "PR 25 D-01: never served after expiry");
        assertTrue(db.captures().findLive(held, now).isPresent(), "a hold keeps it");

        CaptureStore.Deleted d = db.captures().deleteExpired(now);
        assertEquals(1, d.records());
        assertEquals(1, d.chunkIds().size(), "only the chunk no other record references");
        assertEquals(1, refs(shared));
        assertTrue(db.captures().findLive(fresh, now).isPresent());
        assertEquals(500, db.captures().usage());
        assertEquals(1, audit("capture_record", "DELETE"));
        assertEquals(1, audit("capture_chunk", "DELETE"));
        assertEquals(1, audit("capture_deletion_receipt", "INSERT"));
        assertEquals(1, db.dsl().select(Schema.RCPT_CHUNKS).from(Schema.CAPTURE_RECEIPT).fetchOne(Schema.RCPT_CHUNKS));
        assertEquals(CaptureStore.Deleted.NONE, db.captures().deleteExpired(now));
    }

    @Test
    void theByteCapEvictsOldestFirst() {
        Instant now = Instant.now();
        UUID oldest = stored(now.minus(3, ChronoUnit.HOURS), now.plus(80, ChronoUnit.DAYS), "cap-a",
            chunk(address(), 100, "cap-a"));
        UUID held = stored(now.minus(4, ChronoUnit.HOURS), now.plus(80, ChronoUnit.DAYS), "cap-a",
            chunk(address(), 100, "cap-a"));
        UUID newest = stored(now, now.plus(90, ChronoUnit.DAYS), "cap-a", chunk(address(), 100, "cap-a"));
        db.captures().setLegalHold(held, true, HOLD);
        assertEquals(1, db.captures().evictOldest(1).records());
        assertTrue(db.captures().findLive(oldest, now).isEmpty());
        assertTrue(db.captures().findLive(held, now).isPresent(), "a hold is never evicted");
        assertTrue(db.captures().findLive(newest, now).isPresent());
        assertEquals("STORE_CAP_EVICTED", db.dsl().select(Schema.RCPT_REASON).from(Schema.CAPTURE_RECEIPT).fetchOne(0));
    }

    @Test
    void plannedRotationRewrapsAndEmergencyShreddingIsAKeyEvent() {
        Instant now = Instant.now();
        String oldChunk = address();
        UUID a = stored(now, now.plus(90, ChronoUnit.DAYS), "cap-old", chunk(oldChunk, 100, "cap-old"));
        UUID b = stored(now, now.plus(90, ChronoUnit.DAYS), "cap-old", chunk(address(), 100, "cap-old"));
        assertEquals(2, db.captures().recordsToRewrap(Set.of("cap-old"), now, 10).size());
        assertEquals(2, db.captures().chunksToRewrap(Set.of("cap-old"), 10).size());
        var chunkA = db.captures().manifest(a).get(0);
        int n = db.captures().applyRewrap(
            List.of(new CaptureStore.Rewrap(a, "cap-old", "cap-new", random(60))),
            List.of(new CaptureStore.Rewrap(chunkA.chunkId(), "cap-old", "cap-new", random(60))));
        assertEquals(2, n);
        assertEquals(0, db.captures().applyRewrap(
            List.of(new CaptureStore.Rewrap(a, "cap-old", "cap-new", random(60))), List.of()), "only from the old key");
        assertEquals(1, audit("capture_key_event", "INSERT"));
        assertEquals(2, audit("capture_record", "UPDATE") + audit("capture_chunk", "UPDATE"));
        assertEquals(Set.of("cap-old", "cap-new"), db.captures().keysInUse());

        CaptureStore.Deleted shred = db.captures().deleteShredded("cap-old");
        assertEquals(1, shred.records(), "the record still under the shredded key");
        assertTrue(db.captures().findLive(b, now).isEmpty());
        assertTrue(db.captures().findLive(a, now).isPresent(), "the re-wrapped record survives");
        assertEquals("EMERGENCY_SHRED", db.dsl().select(Schema.KE_OPERATION).from(Schema.CAPTURE_KEY_EVENT)
            .where(Schema.KE_OPERATION.eq("EMERGENCY_SHRED")).fetchOne(0));
        assertEquals(Set.of("cap-new"), db.captures().keysInUse());
    }

    /** PR 25 confirmation review D-08: a deduplicated chunk deleted before the insert is sealed and stored inside it. */
    @Test
    void aDeduplicatedChunkThatVanishedIsSealedInsideTheInsert() {
        Instant now = Instant.now();
        String shared = address();
        UUID old = stored(now.minus(1, ChronoUnit.HOURS), now.plus(80, ChronoUnit.DAYS), "cap-a",
            chunk(shared, 400, "cap-a"));
        // The caller decided "already stored"; then an eviction took the last reference before the insert began.
        ChunkPlan known = new ChunkPlan(shared, UUID.randomUUID(), "cap-a", null, 400);
        assertEquals(1, db.captures().evictOldest(10).records());
        assertTrue(db.captures().existingChunks(List.of(shared)).isEmpty());

        UUID next = storedEvent();
        List<UUID> created = new ArrayList<>();
        var inserted = db.captures().insert(record(next, now, now.plus(90, ChronoUnit.DAYS), "cap-a"), List.of(known),
            created::add, a -> chunk(a, 400, "cap-a"));
        assertTrue(inserted.stored());
        assertEquals(1, created.size(), "the vanished chunk was stored again");
        assertEquals(1, refs(shared));
        assertEquals(400, db.captures().usage());
        assertTrue(db.captures().findLive(old, now).isEmpty());

        UUID third = storedEvent();
        String gone = address();
        assertThrows(IllegalStateException.class, () -> db.captures().insert(
            record(third, now, now.plus(90, ChronoUnit.DAYS), "cap-a"),
            List.of(new ChunkPlan(gone, UUID.randomUUID(), "cap-a", null, 1)), c -> { }, a -> null));
        assertTrue(db.captures().findLive(third, now).isEmpty(), "rolled back whole");
    }

    /** D-09: re-wrap pages only rows under mounted keys; Health counts rows under shredded and missing keys apart. */
    @Test
    void rewrapSkipsUnmountedKeysAndTotalsReportThemApart() {
        Instant now = Instant.now();
        for (int i = 0; i < 3; i++) {
            UUID held = stored(now, now.plus(90, ChronoUnit.DAYS), "cap-shredded", chunk(address(), 100, "cap-shredded"));
            db.captures().setLegalHold(held, true, HOLD);
        }
        stored(now, now.plus(90, ChronoUnit.DAYS), "cap-missing", chunk(address(), 100, "cap-missing"));
        UUID rotating = stored(now, now.plus(90, ChronoUnit.DAYS), "cap-old", chunk(address(), 100, "cap-old"));
        stored(now, now.plus(90, ChronoUnit.DAYS), "cap-new", chunk(address(), 100, "cap-new"));
        List<CaptureRecord> page = db.captures().recordsToRewrap(Set.of("cap-old"), now, 2);
        assertEquals(List.of(rotating), page.stream().map(CaptureRecord::eventId).toList(),
            "rows under unmounted keys never fill the page");
        assertEquals(1, db.captures().chunksToRewrap(Set.of("cap-old"), 2).size());
        assertTrue(db.captures().recordsToRewrap(Set.of(), now, 2).isEmpty());

        CaptureStore.Totals t = db.captures().totals("cap-new", Set.of("cap-new", "cap-old"), Set.of("cap-shredded"));
        assertEquals(1, t.recordsUnderOtherKeys(), "a rotation still to re-wrap");
        assertEquals(1, t.chunksUnderOtherKeys());
        assertEquals(3, t.recordsUnderShreddedKeys(), "held records an emergency shred left");
        assertEquals(1, t.recordsUnderMissingKeys(), "under a key neither mounted nor shredded");
    }

    @Test
    void readsAreLedgeredAndAppendOnly() {
        UUID id = UUID.randomUUID();
        db.captures().recordRead(id, "USR-00000000bb", "INCIDENT_INVESTIGATION", "CASE-0001", "SERVED");
        db.captures().recordRead(id, "USR-00000000bb", "NONE", null, "REFUSED_ROLE");
        db.captures().recordRead(id, "USR-00000000bb", "DSAR", "DSAR-0001", "INTEGRITY_FAILED");
        assertEquals(3, audit("capture_read", "INSERT"));
        assertThrows(DataAccessException.class,
            () -> db.captures().recordRead(id, "USR-00000000bb", "NONE", null, "SERVED"),
            "a served read always carries a reason and a case");
        assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            new AuditContext("USR-00000000bb", "x", "y", null).apply(DSL.using(cfg));
            DSL.using(cfg).deleteFrom(Schema.CAPTURE_READ).execute();
        }));
    }
}
