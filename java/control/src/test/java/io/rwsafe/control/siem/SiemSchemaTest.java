package io.rwsafe.control.siem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    /** An e-mail-shaped synthetic value, assembled at runtime (AGENTS.md 4.5: no address literal in the tree). */
    private static final String EMAIL = "first.last" + '@' + "example.test";
    private static final io.rwsafe.persistence.SiemExportStore.AuditPosition POSITION =
        new io.rwsafe.persistence.SiemExportStore.AuditPosition(1, 1);
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
        assertEquals(List.of("stream", "eventClassId", "name", "severity", "time", "values", "verdictPosition",
                "auditPosition"),
            Arrays.stream(SiemRecord.class.getRecordComponents()).map(RecordComponent::getName).toList(),
            "every exported value is a SiemField value; the other components are fixed vocabulary or positions");
        assertEquals(List.of("field", "text"),
            Arrays.stream(SiemRecord.Value.class.getRecordComponents()).map(RecordComponent::getName).toList());
    }

    @Test
    void aRecordRefusesAFieldOfTheOtherStreamOrATwiceSetField() {
        assertThrows(IllegalArgumentException.class, () -> new SiemRecord(SiemStream.AUDIT, "a", "n", 3, Rows.AT,
            List.of(new SiemRecord.Value(SiemField.VERDICT, "BLOCK")), null, POSITION));
        assertThrows(IllegalArgumentException.class, () -> new SiemRecord(SiemStream.AUDIT, "a", "n", 3, Rows.AT,
            List.of(new SiemRecord.Value(SiemField.REASON, "A"), new SiemRecord.Value(SiemField.REASON, "B")), null,
            POSITION));
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

    /**
     * PR 23 review D-2: a row key leaves as written only in its table's exact shape; an account key becomes the
     * account's USR- pseudonym, any other key (an e-mail address, a host name, an address, an account, an estate term)
     * a keyed KEY- pseudonym, and a value that cannot be pseudonymised is withheld.
     */
    @Test
    void rowKeysLeaveOnlyInAllowListedShapesOtherwisePseudonymised() {
        SiemRecords records = new SiemRecords(account -> "USR-" + "ab".repeat(5), key -> "KEY-" + "cd".repeat(2),
            List.of("synthetic-estate"));
        assertEquals("USR-ababababab", rowKey(records, "local_account", "synthetic-glass"));
        assertEquals("class.TCKN@v2:security_admin", rowKey(records, "policy_approval", "class.TCKN@v2:security_admin"));
        assertEquals("platform.openai@v3", rowKey(records, "policy_rule_version", "platform.openai@v3"));
        assertEquals("42", rowKey(records, "login_record", "42"));
        assertEquals("hec", rowKey(records, "siem_watermark", "hec"));
        // PR 25, ADR-009 §4: a capture deletion reaches the SIEM with the event id it can purge, and its receipt number.
        String eventId = java.util.UUID.randomUUID().toString();
        assertEquals(eventId, rowKey(records, "capture_record", eventId));
        assertEquals("7", rowKey(records, "capture_deletion_receipt", "7"));
        assertEquals("KEY-cdcd", rowKey(records, "capture_record", EMAIL), "anything but a UUID is pseudonymised");
        String[] identities = {EMAIL, "host-01.example.test", "192.0.2.10", "2001:db8::10",
            "synthetic.account", "someaccount", "first last", io.rwsafe.control.support.Synthetic.tckn(4)};
        for (String table : new String[] {"some_future_table", "login_record", "policy_snapshot"}) {
            for (String key : identities) {
                assertEquals("KEY-cdcd", rowKey(records, table, key), table + " with an identity-shaped key");
            }
        }
        assertEquals("KEY-cdcd", rowKey(records, "policy_rule_version", "class.synthetic-estate@v1"),
            "a key in its table's shape that holds an estate term is pseudonymised");
        assertEquals("KEY-cdcd", rowKey(records, "siem_watermark", "udp"));

        SiemRecords keyMissing = new SiemRecords(account -> {
            throw new IllegalStateException("privacy key");
        }, key -> {
            throw new IllegalStateException("privacy key");
        }, List.of());
        assertEquals(SiemRecords.WITHHELD, rowKey(keyMissing, "local_account", "synthetic-glass"));
        assertEquals(SiemRecords.WITHHELD, rowKey(keyMissing, "some_table", EMAIL));
        assertFalse(records.ledger(Rows.ledger(6, "local_account", "synthetic-glass")).toString()
            .contains("synthetic-glass"));
    }

    /**
     * PR 23 confirmation review D-13: vocabulary values (letters, digits, {@code _}, {@code -}) still cannot carry an
     * identifier or a secret: a TCKN, an unspaced IBAN, a digits-only phone number, access-key and token shapes, all
     * built at runtime; a {@code system:} actor holding an estate term is withheld too.
     */
    @Test
    void vocabularyValuesCannotCarryIdentifiersOrSecrets() {
        SiemRecords records = new SiemRecords(a -> "USR-" + "ab".repeat(5), k -> "KEY-cdcd", List.of("synthetic-estate"));
        String phone = "5" + "3".repeat(2) + "1234567";
        String[] shapes = {io.rwsafe.control.support.Synthetic.tckn(7), io.rwsafe.control.support.Synthetic.iban(7),
            phone, "tel-" + phone, io.rwsafe.control.support.Synthetic.awsKey(),
            io.rwsafe.control.support.Synthetic.githubToken()};
        for (String shape : shapes) {
            io.rwsafe.persistence.StoredVerdictEvent e = new io.rwsafe.persistence.StoredVerdictEvent(
                java.util.UUID.randomUUID(), Rows.AT, "reqmod", shape, shape, shape, Verdict.BLOCK, shape, List.of(), 1,
                1, "USR-0123456789", "241.7.9.0/24", "mtls_verified", 1, shape, "k1");
            SiemRecord r = records.verdict(new io.rwsafe.persistence.SiemExportStore.ExportVerdict(e, Rows.AT, 7));
            for (SiemField f : List.of(SiemField.PLATFORM, SiemField.SURFACE, SiemField.STEP, SiemField.REASON,
                SiemField.CORRELATION_ID)) {
                String v = r.value(f);
                assertEquals(SiemRecords.WITHHELD, v == null ? SiemRecords.WITHHELD : v, f.name());
            }
            SiemRecord a = records.ledger(new io.rwsafe.persistence.SiemExportStore.LedgerRow(1, 2, Rows.AT,
                "USR-0123456789", "policy.approve", shape, shape, "policy_approval", "INSERT", "x"));
            assertEquals(SiemRecords.WITHHELD, a.value(SiemField.REASON));
            assertEquals(SiemRecords.WITHHELD, a.value(SiemField.CORRELATION_ID));
        }
        SiemRecord ok = records.verdict(Rows.verdict(Verdict.ALLOW, "openai", "customer_data"));
        assertEquals("openai", ok.value(SiemField.PLATFORM));
        assertEquals("customer_data", ok.value(SiemField.REASON));
        assertEquals("corr-1", ok.value(SiemField.CORRELATION_ID), "a short token with digits still leaves");
        SiemRecord estateActor = records.ledger(new io.rwsafe.persistence.SiemExportStore.LedgerRow(1, 2, Rows.AT,
            "system:synthetic-estate", "policy.approve", "R", null, "policy_approval", "INSERT", "x"));
        assertEquals(SiemRecords.WITHHELD, estateActor.value(SiemField.USER));
    }

    @Test
    void everyOtherValueMustMatchItsShapeAndHoldNoEstateTerm() {
        SiemRecords records = new SiemRecords(a -> "USR-" + "ab".repeat(5), k -> "KEY-cdcd", List.of("synthetic-estate"));
        io.rwsafe.persistence.StoredVerdictEvent odd = new io.rwsafe.persistence.StoredVerdictEvent(
            java.util.UUID.randomUUID(), Rows.AT, "reqmod", "synthetic-estate-chat", "web.example.test", "chat",
            Verdict.BLOCK, EMAIL, List.of(), 1, 1, "first.last", "192.0.2.10",
            "mtls_verified", 1, "host-01.example.test", "k1");
        SiemRecord r = records.verdict(new io.rwsafe.persistence.SiemExportStore.ExportVerdict(odd, Rows.AT, 7));
        for (SiemField f : List.of(SiemField.PLATFORM, SiemField.SURFACE, SiemField.REASON, SiemField.USER,
            SiemField.CLIENT_SUBNET, SiemField.CORRELATION_ID)) {
            assertEquals(SiemRecords.WITHHELD, r.value(f), f.name());
        }
        assertEquals("chat", r.value(SiemField.STEP));
        io.rwsafe.persistence.SiemExportStore.LedgerRow ledger = new io.rwsafe.persistence.SiemExportStore.LedgerRow(
            1, 2, Rows.AT, "first.last", "policy.synthetic-estate", "R", EMAIL, "local_account",
            "INSERT", "x");
        SiemRecord a = records.ledger(ledger);
        assertEquals(SiemRecords.WITHHELD, a.value(SiemField.USER));
        assertEquals(SiemRecords.WITHHELD, a.value(SiemField.ACTION));
        assertEquals(SiemRecords.WITHHELD, a.value(SiemField.CORRELATION_ID));
    }

    /**
     * The one free-text value of the ledger (a retirement or withdrawal reason) leaves only through the free-text masker
     * (MASKING_AND_PRIVACY B2): names, hosts and identifiers as tokens; without the masker it is withheld.
     */
    @Test
    void aFreeTextLedgerReasonLeavesOnlyThroughTheFreeTextMasker(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir)
        throws java.io.IOException {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        java.nio.file.Files.write(dir.resolve("key"), key);
        java.nio.file.Files.writeString(dir.resolve("dictionary.txt"), "synthetic-estate\n");
        io.rwsafe.control.privacy.PrivacyKeys keys = new io.rwsafe.control.privacy.PrivacyKeys(
            new io.rwsafe.control.config.ControlProperties(null, null, new io.rwsafe.control.config.ControlProperties
                .Privacy(dir.resolve("key"), dir.resolve("dictionary.txt")), null, null, null, null));
        io.rwsafe.control.privacy.Pseudonymiser p = new io.rwsafe.control.privacy.Pseudonymiser(keys);
        io.rwsafe.control.privacy.TextMasker masker = new io.rwsafe.control.privacy.Masking(keys, p).masker();
        SiemRecords records = new SiemRecords(p::user, k -> p.token("KEY", k), keys.estateTerms(),
            masker::maskFreeText);
        String tckn = io.rwsafe.control.support.Synthetic.tckn(3);
        for (String[] c : new String[][] {
            {"Ayşe Yılmaz asked, see node7.example.com", "NAME-[A-Z]{8} asked, see HST-[0-9a-f]{4}"},
            {"moved off synthetic-estate", "moved off EST-[0-9a-f]{4}"},
            {"customer " + tckn, "customer TCKN-[0-9a-f]{4}"},
            {"APPROVAL_SECURITY_ADMIN", "APPROVAL_SECURITY_ADMIN"}}) {
            io.rwsafe.persistence.SiemExportStore.LedgerRow row = new io.rwsafe.persistence.SiemExportStore.LedgerRow(
                1, 2, Rows.AT, "USR-0123456789", "policy.platform_retire", c[0], "corr-2", "policy_rule_version",
                "UPDATE", "platform.github@v1");
            String reason = records.ledger(row).value(SiemField.REASON);
            assertTrue(reason.matches(c[1]), reason);
            if (!c[0].equals(c[1])) {
                assertEquals(SiemRecords.WITHHELD, Rows.RECORDS.ledger(row).value(SiemField.REASON),
                    "without the free-text masker a sentence is withheld");
            }
        }
    }

    private static String rowKey(SiemRecords records, String table, String key) {
        return records.ledger(Rows.ledger(1, table, key)).value(SiemField.ROW_KEY);
    }

    private static Set<String> keys(JsonNode n) {
        Set<String> out = new TreeSet<>();
        n.fieldNames().forEachRemaining(out::add);
        return out;
    }
}
