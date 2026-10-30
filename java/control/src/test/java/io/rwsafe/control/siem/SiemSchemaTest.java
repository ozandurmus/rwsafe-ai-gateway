package io.rwsafe.control.siem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.rwsafe.control.siem.SiemField.SiemStream;
import io.rwsafe.platform.verdict.Verdict;
import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * SR-SIEM-2: the SIEM event schema has no body field. The field set is fixed and listed here; a new field fails this test
 * until it is added on purpose, and no field name may suggest content or a raw identity.
 */
class SiemSchemaTest {

    private static final List<String> FORBIDDEN = List.of("body", "prompt", "response", "content", "payload", "claim",
        "address", "raw", "text", "message", "password", "secret", "token", "email", "name");

    static final Set<String> VERDICT_EVENT_KEYS = Set.of("eventClass", "severity", "eventId", "stream", "verdict", "reason",
        "usrName", "clientSubnet", "platform", "surface", "step", "findingClasses", "correlationId", "service", "transport",
        "sizeBytes", "decisionMicros", "policySnapshotVersion");
    static final Set<String> AUDIT_EVENT_KEYS = Set.of("eventClass", "severity", "eventId", "stream", "action", "reason",
        "usrName", "auditedTable", "operation", "rowKey", "correlationId");
    static final Set<String> HEC_ENVELOPE_KEYS = Set.of("time", "host", "source", "sourcetype", "index", "event");

    @Test
    void theFieldSetIsExactlyTheApprovedOne() {
        assertEquals(new TreeSet<>(List.of("EVENT_ID", "STREAM", "REASON", "USER", "CORRELATION_ID", "VERDICT",
                "CLIENT_SUBNET", "PLATFORM", "SURFACE", "STEP", "FINDINGS", "SERVICE", "TRANSPORT", "SIZE_BYTES",
                "DECISION_MICROS", "POLICY_SNAPSHOT_VERSION", "ACTION", "AUDITED_TABLE", "OPERATION", "ROW_KEY")),
            EnumSet.allOf(SiemField.class).stream().map(Enum::name).collect(Collectors.toCollection(TreeSet::new)));
    }

    @Test
    void noFieldNameSuggestsABodyOrARawIdentity() {
        for (SiemField f : SiemField.values()) {
            List<String> names = new ArrayList<>(List.of(f.name(), f.key(), f.cefKey()));
            if (f.cefLabel() != null) {
                names.add(f.cefLabel());
            }
            for (String n : names) {
                String lower = n.toLowerCase(Locale.ROOT);
                for (String bad : FORBIDDEN) {
                    if (lower.contains(bad) && !(bad.equals("name") && n.equals("usrName"))) {
                        throw new AssertionError(f + " has a field name containing '" + bad + "': " + n);
                    }
                }
            }
        }
    }

    @Test
    void theRecordHasNoFreeFormSlot() {
        assertEquals(List.of("stream", "eventClassId", "name", "severity", "time", "values", "verdictPosition", "auditId"),
            Arrays.stream(SiemRecord.class.getRecordComponents()).map(RecordComponent::getName).toList(),
            "every exported value is a SiemField value; the other components are fixed vocabulary or positions");
        assertEquals(List.of("field", "text"),
            Arrays.stream(SiemRecord.Value.class.getRecordComponents()).map(RecordComponent::getName).toList());
    }

    @Test
    void aRecordRefusesAFieldOfTheOtherStreamOrATwiceSetField() {
        assertThrows(IllegalArgumentException.class, () -> new SiemRecord(SiemStream.AUDIT, "a", "n", 3, Rows.AT,
            List.of(new SiemRecord.Value(SiemField.VERDICT, "BLOCK")), null, 1));
        assertThrows(IllegalArgumentException.class, () -> new SiemRecord(SiemStream.AUDIT, "a", "n", 3, Rows.AT,
            List.of(new SiemRecord.Value(SiemField.REASON, "A"), new SiemRecord.Value(SiemField.REASON, "B")), null, 1));
    }

    @Test
    void hecEventsCarryOnlyTheFixedKeys() throws Exception {
        ObjectMapper json = new ObjectMapper();
        JsonNode verdict = json.readTree(SiemFormats.hec(
            Rows.RECORDS.verdict(Rows.verdict(Verdict.BLOCK, "openai", "customer_data")), "rwsafe-control", "idx"));
        assertEquals(HEC_ENVELOPE_KEYS, keys(verdict));
        assertEquals(VERDICT_EVENT_KEYS, keys(verdict.get("event")));
        JsonNode audit = json.readTree(SiemFormats.hec(
            Rows.RECORDS.ledger(Rows.ledger(9, "policy_approval", "class.TCKN@v2:security_admin")), "h", "idx"));
        assertEquals(AUDIT_EVENT_KEYS, keys(audit.get("event")));
    }

    @Test
    void identityKeyedLedgerRowsArePseudonymisedAndOddKeysWithheld() {
        SiemRecords records = new SiemRecords(account -> "USR-" + "ab".repeat(5));
        assertEquals("USR-ababababab",
            records.ledger(Rows.ledger(1, "local_account", "synthetic-glass")).value(SiemField.ROW_KEY));
        assertEquals("class.TCKN@v2:security_admin",
            records.ledger(Rows.ledger(2, "policy_approval", "class.TCKN@v2:security_admin")).value(SiemField.ROW_KEY));
        assertEquals(SiemRecords.WITHHELD,
            records.ledger(Rows.ledger(3, "some_table", "first last")).value(SiemField.ROW_KEY), "not a token");
        assertEquals(SiemRecords.WITHHELD, records.ledger(Rows.ledger(4, "some_table",
            io.rwsafe.control.support.Synthetic.tckn(4))).value(SiemField.ROW_KEY), "a detector hit");
        SiemRecords keyMissing = new SiemRecords(account -> {
            throw new IllegalStateException("privacy key");
        });
        assertEquals(SiemRecords.WITHHELD,
            keyMissing.ledger(Rows.ledger(5, "local_account", "synthetic-glass")).value(SiemField.ROW_KEY),
            "without the privacy key the account name is withheld, never sent");
        assertFalse(records.ledger(Rows.ledger(6, "local_account", "synthetic-glass")).toString()
            .contains("synthetic-glass"));
    }

    private static Set<String> keys(JsonNode n) {
        Set<String> out = new TreeSet<>();
        n.fieldNames().forEachRemaining(out::add);
        return out;
    }
}
