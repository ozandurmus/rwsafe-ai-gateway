package io.rwsafe.control.siem;

/**
 * The complete, fixed SIEM event schema (ADR-009 C8: C1, C2, C6 and C7 fields only; SR-SIEM-2). No member can hold a
 * prompt or response body, a raw identity claim or a raw client address: users are {@code USR-} pseudonyms or
 * {@code system:} actors, the client is a masked /24 label, findings are class and count. {@code SiemSchemaTest} proves
 * the set; a new field is a change to this enum and to that test.
 *
 * <p>Each field names its CEF extension key (a standard key where one fits, otherwise a custom-string or custom-number
 * slot with its label; the slots are reused across the two streams under different labels) and the key it carries in LEEF
 * and in the HEC event object.
 */
public enum SiemField {

    // Both streams.
    EVENT_ID(SiemStream.BOTH, "externalId", null, "eventId", 64, false),
    STREAM(SiemStream.BOTH, "cat", null, "stream", 16, false),
    REASON(SiemStream.BOTH, "reason", null, "reason", 64, false),
    USER(SiemStream.BOTH, "suser", null, "usrName", 48, false),
    CORRELATION_ID(SiemStream.BOTH, "cs6", "correlationId", "correlationId", 64, false),

    // Verdict events (C1, C2, C6).
    VERDICT(SiemStream.VERDICT, "act", null, "verdict", 32, false),
    CLIENT_SUBNET(SiemStream.VERDICT, "cs1", "clientSubnet", "clientSubnet", 24, false),
    PLATFORM(SiemStream.VERDICT, "cs2", "platform", "platform", 64, false),
    SURFACE(SiemStream.VERDICT, "cs3", "surface", "surface", 32, false),
    STEP(SiemStream.VERDICT, "cs4", "step", "step", 32, false),
    FINDINGS(SiemStream.VERDICT, "cs5", "findingClasses", "findingClasses", 1000, false),
    SERVICE(SiemStream.VERDICT, "flexString1", "service", "service", 16, false),
    TRANSPORT(SiemStream.VERDICT, "flexString2", "transport", "transport", 32, false),
    SIZE_BYTES(SiemStream.VERDICT, "cn1", "sizeBytes", "sizeBytes", 20, true),
    DECISION_MICROS(SiemStream.VERDICT, "cn2", "decisionMicros", "decisionMicros", 20, true),
    POLICY_SNAPSHOT_VERSION(SiemStream.VERDICT, "cn3", "policySnapshotVersion", "policySnapshotVersion", 20, true),

    // Audit-ledger rows (C7).
    ACTION(SiemStream.AUDIT, "act", null, "action", 64, false),
    AUDITED_TABLE(SiemStream.AUDIT, "cs1", "auditedTable", "auditedTable", 64, false),
    OPERATION(SiemStream.AUDIT, "cs2", "operation", "operation", 16, false),
    ROW_KEY(SiemStream.AUDIT, "cs3", "rowKey", "rowKey", 96, false);

    /** Which stream a field belongs to. */
    public enum SiemStream { VERDICT, AUDIT, BOTH }

    private final SiemStream stream;
    private final String cefKey;
    private final String cefLabel;
    private final String key;
    private final int maxLength;
    private final boolean numeric;

    SiemField(SiemStream stream, String cefKey, String cefLabel, String key, int maxLength, boolean numeric) {
        this.stream = stream;
        this.cefKey = cefKey;
        this.cefLabel = cefLabel;
        this.key = key;
        this.maxLength = maxLength;
        this.numeric = numeric;
    }

    public SiemStream stream() {
        return stream;
    }

    /** The CEF extension key. */
    public String cefKey() {
        return cefKey;
    }

    /** The label of a custom slot ({@code cs1Label=clientSubnet}); null for a standard key. */
    public String cefLabel() {
        return cefLabel;
    }

    /** The LEEF attribute and HEC event key. */
    public String key() {
        return key;
    }

    public int maxLength() {
        return maxLength;
    }

    public boolean numeric() {
        return numeric;
    }

    boolean allowedIn(SiemStream recordStream) {
        return stream == SiemStream.BOTH || stream == recordStream;
    }
}
