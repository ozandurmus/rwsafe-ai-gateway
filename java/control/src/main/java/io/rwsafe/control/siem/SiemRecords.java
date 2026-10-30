package io.rwsafe.control.siem;

import io.rwsafe.control.siem.SiemField.SiemStream;
import io.rwsafe.control.siem.SiemRecord.Value;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.persistence.FindingCount;
import io.rwsafe.persistence.SiemExportStore.ExportVerdict;
import io.rwsafe.persistence.SiemExportStore.LedgerRow;
import io.rwsafe.persistence.StoredVerdictEvent;
import io.rwsafe.platform.verdict.Verdict;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * Maps stored rows to {@link SiemRecord}s: the only place that decides what leaves for the SIEM (ADR-009 C8, SR-SIEM-2).
 * Verdict events are already pseudonymised at ingestion. Ledger rows carry a pseudonymous actor; their row key is the
 * audited table's key and can be an account name, so identity tables' keys are pseudonymised here under rwsafe's own key
 * (the same {@code USR-} the account's sign-ins carry) and any other key leaves only when it is a plain token that no
 * Tier-1 detector recognises. Anything else is {@value #WITHHELD}: fail closed, never the value.
 */
public final class SiemRecords {

    public static final String WITHHELD = "[WITHHELD]";

    /** Audited tables whose row key names a person or an account. */
    static final Set<String> IDENTITY_KEYED_TABLES = Set.of("local_account");
    private static final DetectorSet DETECTORS = DetectorSet.standard();

    private final Function<String, String> accountPseudonym;

    /**
     * @param accountPseudonym the account name's {@code USR-} pseudonym; may throw when the privacy key is missing, and
     *                         the row key is then withheld
     */
    public SiemRecords(Function<String, String> accountPseudonym) {
        this.accountPseudonym = accountPseudonym;
    }

    public SiemRecord verdict(ExportVerdict row) {
        StoredVerdictEvent e = row.event();
        List<Value> v = new ArrayList<>();
        v.add(new Value(SiemField.EVENT_ID, e.eventId().toString()));
        v.add(new Value(SiemField.STREAM, "verdict"));
        v.add(new Value(SiemField.VERDICT, e.verdict().name()));
        v.add(new Value(SiemField.REASON, e.reason()));
        v.add(new Value(SiemField.USER, e.userPseudonym()));
        v.add(new Value(SiemField.CLIENT_SUBNET, e.clientSubnet()));
        v.add(new Value(SiemField.PLATFORM, e.platform()));
        v.add(new Value(SiemField.SURFACE, e.surface()));
        v.add(new Value(SiemField.STEP, e.step()));
        v.add(new Value(SiemField.FINDINGS, findings(e.findings())));
        v.add(new Value(SiemField.CORRELATION_ID, e.correlationId()));
        v.add(new Value(SiemField.SERVICE, e.service()));
        v.add(new Value(SiemField.TRANSPORT, e.transport()));
        v.add(new Value(SiemField.SIZE_BYTES, Long.toString(e.bodyBytes())));
        v.add(new Value(SiemField.DECISION_MICROS, Long.toString(e.decisionMicros())));
        v.add(new Value(SiemField.POLICY_SNAPSHOT_VERSION, Long.toString(e.snapshotVersion())));
        return new SiemRecord(SiemStream.VERDICT, "verdict." + e.verdict().name(), "AI usage verdict " + e.verdict().name(),
            severity(e.verdict()), e.receivedAt(), v, row.position(), 0);
    }

    public SiemRecord ledger(LedgerRow row) {
        List<Value> v = new ArrayList<>();
        String action = token(row.actionId(), 64) ? row.actionId() : WITHHELD;
        v.add(new Value(SiemField.EVENT_ID, "audit-" + row.auditId()));
        v.add(new Value(SiemField.STREAM, "audit"));
        v.add(new Value(SiemField.ACTION, action));
        v.add(new Value(SiemField.REASON, token(row.reasonCode(), 64) ? row.reasonCode() : WITHHELD));
        v.add(new Value(SiemField.USER, actor(row.actorFingerprint()) ? row.actorFingerprint() : WITHHELD));
        v.add(new Value(SiemField.AUDITED_TABLE, token(row.tableName(), 64) ? row.tableName() : WITHHELD));
        v.add(new Value(SiemField.OPERATION, operation(row.operation()) ? row.operation() : WITHHELD));
        v.add(new Value(SiemField.ROW_KEY, rowKey(row.tableName(), row.rowKey())));
        String correlation = row.correlationId();
        v.add(new Value(SiemField.CORRELATION_ID,
            correlation == null || correlation.isEmpty() ? null : token(correlation, 64) ? correlation : WITHHELD));
        return new SiemRecord(SiemStream.AUDIT, "audit." + action, "Audit " + action, 3, row.occurredAt(), v, null,
            row.auditId());
    }

    /** CEF severity: allow 1, warn 4, redact 5, non-verdicts 6, block and an aborted stream 7. */
    static int severity(Verdict verdict) {
        return switch (verdict) {
            case ALLOW -> 1;
            case WARN -> 4;
            case REDACT -> 5;
            case BLOCK, STREAM_ABORTED -> 7;
            case UNINSPECTABLE, MALFORMED, INSPECTION_FAILED, INSPECTION_TIMEOUT, UNKNOWN_FLOW -> 6;
        };
    }

    /** {@code TCKN:2,SECRET:1}: classes and counts, never a value or a digest. */
    static String findings(List<FindingCount> findings) {
        StringBuilder s = new StringBuilder();
        for (FindingCount f : findings) {
            if (!s.isEmpty()) {
                s.append(',');
            }
            s.append(f.dataClass()).append(':').append(f.count());
        }
        return s.toString();
    }

    private String rowKey(String table, String key) {
        if (key == null || key.isEmpty()) {
            return null;
        }
        if (IDENTITY_KEYED_TABLES.contains(table)) {
            try {
                String pseudonym = accountPseudonym.apply(key);
                return actor(pseudonym) ? pseudonym : WITHHELD;
            } catch (RuntimeException keyMissing) {
                return WITHHELD;
            }
        }
        return token(key, 96) ? key : WITHHELD;
    }

    /**
     * Letters, digits and {@code _ - . @ :} (rule ids such as {@code class.TCKN@v2:security_admin}, numeric keys, UUIDs),
     * and nothing a Tier-1 detector recognises, so no identifier or secret shape can pass as a key.
     */
    static boolean token(String s, int max) {
        if (s == null || s.isEmpty() || s.length() > max) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
                || c == '.' || c == '@' || c == ':')) {
                return false;
            }
        }
        return isCanonicalUuid(s) || DETECTORS.scan(s).isEmpty();
    }

    /** {@code USR-<10 hex>} or {@code system:<name>}, the ledger's actor shapes. */
    static boolean actor(String s) {
        if (s == null) {
            return false;
        }
        if (s.startsWith("system:")) {
            String name = s.substring("system:".length());
            return !name.isEmpty() && name.length() <= 32
                && name.chars().allMatch(c -> (c >= 'a' && c <= 'z') || c == '_' || c == '-');
        }
        return s.length() == 14 && s.startsWith("USR-")
            && s.substring(4).chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }

    private static boolean operation(String s) {
        return "INSERT".equals(s) || "UPDATE".equals(s) || "DELETE".equals(s);
    }

    private static boolean isCanonicalUuid(String s) {
        if (s.length() != 36) {
            return false;
        }
        try {
            return java.util.UUID.fromString(s).toString().equals(s);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
