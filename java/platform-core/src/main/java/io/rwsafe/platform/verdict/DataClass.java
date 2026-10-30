package io.rwsafe.platform.verdict;

/**
 * The deterministic DLP classes the Tier-1 detectors emit (SECURITY_REQUIREMENTS SR-DLP-1). Every class here belongs to
 * a fail-closed category: {@code secret} or {@code customer_data}. A finding names its class and offsets, never its value.
 */
public enum DataClass {
    SECRET("secret", "SECRET"),
    TCKN("customer_data", "TCKN"),
    TR_IBAN("customer_data", "IBAN"),
    PAYMENT_CARD("customer_data", "CARD");

    private final String category;
    private final String tokenLabel;

    DataClass(String category, String tokenLabel) {
        this.category = category;
        this.tokenLabel = tokenLabel;
    }

    /** The registry category (SR-DLP-1): {@code secret}, {@code customer_data}. */
    public String category() {
        return category;
    }

    /** Every Tier-1 class is in a fail-closed category (SR-DLP-1). */
    public boolean failClosed() {
        return true;
    }

    /** The replacement written into a redacted request, for example {@code [REDACTED:TCKN]} (ICAP spec §4.3). */
    public String redactionToken() {
        return "[REDACTED:" + tokenLabel + "]";
    }
}
