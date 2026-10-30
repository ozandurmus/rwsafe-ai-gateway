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
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

/**
 * Maps stored rows to {@link SiemRecord}s: the only place that decides what leaves for the SIEM (ADR-009 C8, SR-SIEM-2).
 * Every exported value must match the exact shape its field allows; a value that does not, or that contains a term of
 * the estate dictionary, leaves as {@value #WITHHELD} (fail closed, never the value).
 *
 * <p>Audit-ledger row keys (PR 23 review D-2) leave as they are only for the audited tables listed in
 * {@link #rowKeyShape}, only in that table's exact key shape (a number, a policy version key, a destination name) and
 * only when no Tier-1 detector and no estate term matches it.
 * An account key ({@code local_account}) becomes the account's {@code USR-} pseudonym (the one its sign-ins carry); any
 * other key, of any table, becomes a keyed {@code KEY-} pseudonym under rwsafe's own HMAC key (the masking funnel's
 * layer 4 token), so an e-mail address, a host name, an address or an account never leaves as written.
 */
public final class SiemRecords {

    public static final String WITHHELD = "[WITHHELD]";
    private static final DetectorSet DETECTORS = DetectorSet.standard();

    private final Function<String, String> accountPseudonym;
    private final Function<String, String> keyPseudonym;
    private final List<String> estateTerms;

    /**
     * @param accountPseudonym the account name's {@code USR-} pseudonym
     * @param keyPseudonym     a keyed, class-visible token for any other row key ({@code KEY-xxxx})
     * @param estateTerms      the lower-case estate dictionary (masking layer 3)
     */
    public SiemRecords(Function<String, String> accountPseudonym, Function<String, String> keyPseudonym,
                       List<String> estateTerms) {
        this.accountPseudonym = accountPseudonym;
        this.keyPseudonym = keyPseudonym;
        this.estateTerms = List.copyOf(estateTerms);
    }

    public SiemRecord verdict(ExportVerdict row) {
        StoredVerdictEvent e = row.event();
        List<Value> v = new ArrayList<>();
        v.add(new Value(SiemField.EVENT_ID, e.eventId().toString()));
        v.add(new Value(SiemField.STREAM, "verdict"));
        v.add(new Value(SiemField.VERDICT, e.verdict().name()));
        v.add(new Value(SiemField.REASON, e.reason() == null ? null : vocabulary(e.reason(), 64)));
        v.add(new Value(SiemField.USER, e.userPseudonym() == null ? null : actor(e.userPseudonym())
            ? e.userPseudonym() : WITHHELD));
        v.add(new Value(SiemField.CLIENT_SUBNET, e.clientSubnet() == null ? null : subnetLabel(e.clientSubnet())
            ? e.clientSubnet() : WITHHELD));
        v.add(new Value(SiemField.PLATFORM, vocabulary(e.platform(), 64)));
        v.add(new Value(SiemField.SURFACE, vocabulary(e.surface(), 32)));
        v.add(new Value(SiemField.STEP, vocabulary(e.step(), 32)));
        v.add(new Value(SiemField.FINDINGS, findings(e.findings())));
        v.add(new Value(SiemField.CORRELATION_ID, canonicalUuid(e.correlationId()) ? e.correlationId()
            : vocabulary(e.correlationId(), 64)));
        v.add(new Value(SiemField.SERVICE, oneOf(e.service(), Set.of("reqmod", "respmod"))));
        v.add(new Value(SiemField.TRANSPORT, oneOf(e.transport(), Set.of("plain_allowlisted", "mtls_verified"))));
        v.add(new Value(SiemField.SIZE_BYTES, Long.toString(e.bodyBytes())));
        v.add(new Value(SiemField.DECISION_MICROS, Long.toString(e.decisionMicros())));
        v.add(new Value(SiemField.POLICY_SNAPSHOT_VERSION, Long.toString(e.snapshotVersion())));
        return new SiemRecord(SiemStream.VERDICT, "verdict." + e.verdict().name(), "AI usage verdict " + e.verdict().name(),
            severity(e.verdict()), e.receivedAt(), v, row.position(), null);
    }

    public SiemRecord ledger(LedgerRow row) {
        List<Value> v = new ArrayList<>();
        String action = actionId(row.actionId()) && !estate(row.actionId()) ? row.actionId() : WITHHELD;
        String table = tableName(row.tableName()) && !estate(row.tableName()) ? row.tableName() : WITHHELD;
        v.add(new Value(SiemField.EVENT_ID, "audit-" + row.auditId()));
        v.add(new Value(SiemField.STREAM, "audit"));
        v.add(new Value(SiemField.ACTION, action));
        v.add(new Value(SiemField.REASON, vocabulary(row.reasonCode(), 64)));
        v.add(new Value(SiemField.USER, actor(row.actorFingerprint()) ? row.actorFingerprint() : WITHHELD));
        v.add(new Value(SiemField.AUDITED_TABLE, table));
        v.add(new Value(SiemField.OPERATION, oneOf(row.operation(), Set.of("INSERT", "UPDATE", "DELETE"))));
        v.add(new Value(SiemField.ROW_KEY, rowKey(row.tableName(), row.rowKey())));
        String correlation = row.correlationId();
        v.add(new Value(SiemField.CORRELATION_ID, correlation == null || correlation.isEmpty() ? null
            : canonicalUuid(correlation) ? correlation : vocabulary(correlation, 64)));
        return new SiemRecord(SiemStream.AUDIT, "audit." + action, "Audit " + action, 3, row.occurredAt(), v, null,
            row.position());
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
            if (!dataClass(f.dataClass())) {
                continue;
            }
            if (!s.isEmpty()) {
                s.append(',');
            }
            s.append(f.dataClass()).append(':').append(f.count());
        }
        return s.toString();
    }

    /** The exact key shape of each audited table whose key may leave as written; null: never as written. */
    enum KeyShape { ACCOUNT, NUMBER, RULE_VERSION, RULE_APPROVAL, DESTINATION }

    static KeyShape rowKeyShape(String table) {
        return switch (table == null ? "" : table) {
            case "local_account" -> KeyShape.ACCOUNT;
            case "login_record", "policy_snapshot" -> KeyShape.NUMBER;
            case "policy_rule_version" -> KeyShape.RULE_VERSION;
            case "policy_approval" -> KeyShape.RULE_APPROVAL;
            case "siem_watermark" -> KeyShape.DESTINATION;
            default -> null;
        };
    }

    String rowKey(String table, String key) {
        if (key == null || key.isEmpty()) {
            return null;
        }
        KeyShape shape = rowKeyShape(table);
        if (shape == KeyShape.ACCOUNT) {
            return pseudonym(accountPseudonym, key, true);
        }
        boolean asWritten = shape != null && !estate(key) && DETECTORS.scan(key).isEmpty() && switch (shape) {
            case NUMBER -> number(key);
            case RULE_VERSION -> ruleVersion(key);
            case RULE_APPROVAL -> ruleApproval(key);
            case DESTINATION -> key.equals("syslog") || key.equals("hec");
            case ACCOUNT -> false;
        };
        return asWritten ? key : pseudonym(keyPseudonym, key, false);
    }

    private static String pseudonym(Function<String, String> f, String key, boolean user) {
        try {
            String p = f.apply(key);
            boolean ok = user ? actor(p) : p != null && p.startsWith("KEY-") && p.length() <= 16
                && plain(p.substring(4), 12);
            return ok ? p : WITHHELD;
        } catch (RuntimeException keyMissing) {
            return WITHHELD;
        }
    }

    /** A vocabulary token as ingestion accepts it (letters, digits, {@code _}, {@code -}) without an estate term. */
    private String vocabulary(String s, int max) {
        return s != null && plain(s, max) && !estate(s) ? s : WITHHELD;
    }

    private static String oneOf(String s, Set<String> allowed) {
        return allowed.contains(s) ? s : WITHHELD;
    }

    /** True when the value contains a term of the estate dictionary (case-insensitive). */
    boolean estate(String s) {
        String lower = s.toLowerCase(Locale.ROOT);
        for (String term : estateTerms) {
            if (!term.isEmpty() && lower.contains(term)) {
                return true;
            }
        }
        return false;
    }

    /** Letters, digits, {@code _} and {@code -}: no dot, colon or {@code @}, so no host, address or e-mail fits. */
    static boolean plain(String s, int max) {
        if (s == null || s.isEmpty() || s.length() > max) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
                return false;
            }
        }
        return true;
    }

    /** {@code segment(.segment)*}, segments of lower-case letters and {@code _}: the code's action ids. */
    static boolean actionId(String s) {
        if (s == null || s.isEmpty() || s.length() > 64 || s.startsWith(".") || s.endsWith(".") || s.contains("..")) {
            return false;
        }
        return s.chars().allMatch(c -> (c >= 'a' && c <= 'z') || c == '_' || c == '.');
    }

    /** A table name: lower-case letters and {@code _}. */
    static boolean tableName(String s) {
        return s != null && !s.isEmpty() && s.length() <= 63 && s.chars().allMatch(c -> (c >= 'a' && c <= 'z') || c == '_');
    }

    static boolean number(String s) {
        return !s.isEmpty() && s.length() <= 19 && s.chars().allMatch(c -> c >= '0' && c <= '9');
    }

    /** {@code (class|platform|flow).<id>@v<n>}: the policy_rule_version key (V2 CHECK). */
    static boolean ruleVersion(String s) {
        int at = s.lastIndexOf("@v");
        if (at < 0 || !number(s.substring(at + 2)) || s.substring(at + 2).length() > 9) {
            return false;
        }
        String rule = s.substring(0, at);
        for (String kind : new String[] {"class.", "platform.", "flow."}) {
            if (rule.startsWith(kind)) {
                return plain(rule.substring(kind.length()), 64);
            }
        }
        return false;
    }

    /** {@code <rule version>:<approver role>}: the policy_approval key. */
    static boolean ruleApproval(String s) {
        int colon = s.lastIndexOf(':');
        if (colon < 0) {
            return false;
        }
        String role = s.substring(colon + 1);
        return (role.equals("security_admin") || role.equals("privacy_officer")) && ruleVersion(s.substring(0, colon));
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

    /** The stored client label: a /24 in 240.0.0.0/4, or the two fixed markers (V1 CHECK). */
    static boolean subnetLabel(String s) {
        if (s.equals("[REDACTED_IP]") || s.equals("[INVALID_ADDRESS]")) {
            return true;
        }
        if (!s.endsWith(".0/24")) {
            return false;
        }
        String[] parts = s.substring(0, s.length() - ".0/24".length()).split("\\.", -1);
        if (parts.length != 3) {
            return false;
        }
        for (int i = 0; i < 3; i++) {
            if (!number(parts[i]) || parts[i].length() > 3) {
                return false;
            }
            int v = Integer.parseInt(parts[i]);
            if (v > 255 || (i == 0 && v < 240)) {
                return false;
            }
        }
        return true;
    }

    private static boolean dataClass(String s) {
        return s != null && !s.isEmpty() && s.length() <= 32 && s.charAt(0) >= 'A' && s.charAt(0) <= 'Z'
            && s.chars().allMatch(c -> (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_');
    }

    static boolean canonicalUuid(String s) {
        if (s == null || s.length() != 36) {
            return false;
        }
        try {
            return UUID.fromString(s).toString().equals(s);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
