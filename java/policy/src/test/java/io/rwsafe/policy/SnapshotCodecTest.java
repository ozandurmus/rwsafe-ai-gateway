package io.rwsafe.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.rwsafe.platform.verdict.DataClass;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class SnapshotCodecTest {

    private static final Instant NOW = Instant.parse("2026-10-30T18:00:00Z");

    private static String doc(String format, String classes, boolean enforce) {
        return "{\"format\":" + format + ",\"version\":3,\"id\":\"registry-synthetic\",\"issuedAt\":\"2026-10-30T17:00:00Z\","
            + "\"enforceFailClosed\":" + enforce + ",\"classActions\":{" + classes + "},\"platforms\":[]}";
    }

    private static final String ALL = "\"SECRET\":\"BLOCK\",\"TCKN\":\"REDACT\",\"TR_IBAN\":\"REDACT\",\"PAYMENT_CARD\":\"REDACT\"";

    private static String reason(String json) {
        return assertThrows(SnapshotCodec.Rejected.class,
            () -> SnapshotCodec.parse(json.getBytes(StandardCharsets.UTF_8), NOW)).reason();
    }

    @Test
    void parsesAContractDocument() throws Exception {
        PolicySnapshot s = SnapshotCodec.parse(doc("1", ALL, true).getBytes(StandardCharsets.UTF_8), NOW);
        assertEquals(3, s.version());
        assertEquals(Action.REDACT, s.actionFor(DataClass.TCKN));
        assertEquals(Instant.parse("2026-10-30T17:00:00Z"), s.issuedAt());
    }

    @Test
    void refusesAnythingOutsideTheContract() {
        assertEquals("FORMAT", reason(doc("2", ALL, true)));
        assertEquals("MISSING_CLASS", reason(doc("1", "\"SECRET\":\"BLOCK\"", true)));
        assertEquals("UNKNOWN_CLASS_OR_ACTION", reason(doc("1", ALL + ",\"PASSPORT\":\"BLOCK\"", true)));
        assertEquals("UNKNOWN_CLASS_OR_ACTION", reason(doc("1", ALL.replace("\"BLOCK\"", "\"QUARANTINE\""), true)));
        assertEquals("FAIL_CLOSED_WEAKENED", reason(doc("1", ALL.replace("\"BLOCK\"", "\"WARN\""), true)));
        assertEquals("MALFORMED", reason(doc("1", ALL + ",\"TCKN\":\"BLOCK\"", true)));
        assertEquals("MALFORMED", reason(doc("1", ALL, true) + "x"));
        assertEquals("MALFORMED", reason(doc("1", ALL, true).replace("\"version\":3", "\"version\":3.5")));
        assertEquals("STALE", reason(doc("1", ALL, true).replace("2026-10-30T17:00:00Z", "2026-10-29T17:00:00Z")));
        assertEquals("FUTURE", reason(doc("1", ALL, true).replace("2026-10-30T17:00:00Z", "2026-10-30T19:00:00Z")));
    }

    @Test
    void monitorSnapshotsMayRelaxFailClosedClasses() throws Exception {
        PolicySnapshot s = SnapshotCodec.parse(doc("1", ALL.replace("\"BLOCK\"", "\"WARN\""), false)
            .getBytes(StandardCharsets.UTF_8), NOW);
        assertEquals(Action.WARN, s.actionFor(DataClass.SECRET));
    }
}
