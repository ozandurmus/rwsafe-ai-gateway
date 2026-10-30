package io.rwsafe.platform.verdict;

import java.util.HashSet;
import java.util.Set;

/**
 * The closed set of reason codes a verdict event carries (PR 24 review D-01): the fail-closed categories of the DLP
 * classes, and the data plane's non-verdict and stream reasons. The control plane refuses any other value, so the field
 * can never carry an identifier; the data plane's end-to-end test fails when it emits a reason missing here, so a new
 * reason is added here in the same change (drift fails loudly, AGENTS.md section 7).
 */
public final class ReasonCodes {

    /** Every reason code; {@code null} (no reason, an allow) is not in it. */
    public static final Set<String> ALL;

    static {
        Set<String> all = new HashSet<>(Set.of(
            // BodyInspector and the decoding layers
            "OVERSIZE", "ENCODED", "UNSUPPORTED_CHARSET", "BINARY", "MULTIPART", "UNSUPPORTED_MEDIA", "NORMALISATION",
            "FINDING_LIMIT", "JSON", "UNDECODABLE_BLOB", "EMBEDDED_FILE",
            // the connection handler and admission
            "IDENTITY_LIMIT", "ENGINE_FULL", "HTTP_HEAD", "EVENT_BACKPRESSURE", "INTERNAL", "BODY_RECEIVE", "TOO_LARGE",
            "WEBSOCKET_INVISIBLE_AFTER_UPGRADE",
            // the login-step rules (PC-9)
            "NON_CORPORATE_ACCOUNT"));
        for (DataClass c : DataClass.values()) {
            all.add(c.category());
        }
        ALL = Set.copyOf(all);
    }

    private ReasonCodes() {
    }

    public static boolean known(String reason) {
        return reason != null && ALL.contains(reason);
    }
}
