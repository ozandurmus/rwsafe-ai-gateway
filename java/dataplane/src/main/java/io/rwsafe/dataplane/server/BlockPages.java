package io.rwsafe.dataplane.server;

import io.rwsafe.platform.enduser.EndUserCatalogue;
import io.rwsafe.platform.enduser.EndUserPages;
import io.rwsafe.platform.enduser.EndUserPages.BlockKind;
import io.rwsafe.platform.enduser.EndUserParameters;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * The end-user answers of the data plane, rendered from the Turkish catalogue (docs/i18n/tr, {@link EndUserCatalogue}):
 * the block page per reason kind, the API error, the coaching page and the stream-termination message. Every inserted
 * value is escaped; a page loads nothing external and carries only the reference id, never content or identity (SEC-5).
 * Every Tier-1 class is fail-closed, so the block page never offers an exception (PC-5).
 *
 * <p>The catalogue and the configured values ({@code RWSAFE_ENDUSER_*}, read from the environment) are loaded once, when
 * this class initialises; nothing is read per request.
 */
final class BlockPages {

    /** Content-Types of the answers below (the response head is written by the connection handler). */
    static final String HTML_CONTENT_TYPE = EndUserPages.HTML_CONTENT_TYPE;
    static final String JSON_CONTENT_TYPE = "application/json; charset=utf-8";
    static final String TEXT_CONTENT_TYPE = "text/plain; charset=utf-8";

    /** Registry categories that are fail-closed (SR-DLP-1): a block names the class and offers no exception. */
    private static final Set<String> FAIL_CLOSED_CATEGORIES =
        Set.of("secret", "customer_data", "special_category", "internal_identity");
    private static final Set<String> SIZE = Set.of("OVERSIZE", "TOO_LARGE");
    private static final Set<String> ENCODED = Set.of("ENCODED", "NORMALISATION");
    private static final Set<String> FORMAT =
        Set.of("JSON", "BINARY", "MULTIPART", "UNSUPPORTED_MEDIA", "UNSUPPORTED_CHARSET", "HTTP_HEAD");
    private static final Set<String> INCOMPLETE = Set.of("BODY_RECEIVE");
    private static final Set<String> UNAVAILABLE = Set.of("INTERNAL", "EVENT_BACKPRESSURE", "IDENTITY_LIMIT");
    /** Reasons of a platform block (the registry's platform rule; a vendor without its article 9 instrument, Q-33). */
    private static final Set<String> PLATFORM = Set.of("PLATFORM_NOT_ALLOWED", "VENDOR_INSTRUMENT_MISSING");
    /** A personal (non-corporate) account at the login step (Q-6). */
    private static final Set<String> PERSONAL = Set.of("PERSONAL_ACCOUNT");

    private static final EndUserPages PAGES = new EndUserPages(EndUserCatalogue.turkish(),
        EndUserParameters.fromEnvironment(System.getenv()));

    private BlockPages() {
    }

    /** The block page body kind for a decision reason (a registry category or a non-verdict reason). */
    static BlockKind kind(String reason) {
        if (reason == null) {
            return BlockKind.GENERIC;
        }
        if (FAIL_CLOSED_CATEGORIES.contains(reason)) {
            return BlockKind.CLASS;
        }
        if (PLATFORM.contains(reason)) {
            return BlockKind.PLATFORM;
        }
        if (PERSONAL.contains(reason)) {
            return BlockKind.PERSONAL;
        }
        if (UNAVAILABLE.contains(reason)) {
            return BlockKind.UNAVAILABLE;
        }
        if (labelKey(reason) != null) {
            return BlockKind.UNINSPECTABLE;
        }
        return BlockKind.GENERIC;
    }

    /** Turkish label of a registry category or non-verdict reason. */
    static String label(String reason) {
        return PAGES.label(labelKeyOrOther(reason));
    }

    /**
     * The label in the stream-termination message: the class for a fail-closed category; otherwise the limit was reached
     * because of findings or text that hides them (N-01), so "sensitive information".
     */
    static String streamLabel(String reason) {
        return PAGES.label(reason != null && FAIL_CLOSED_CATEGORIES.contains(reason) ? "class." + reason : "class.other");
    }

    private static String labelKey(String reason) {
        if (reason == null) {
            return null;
        }
        if (FAIL_CLOSED_CATEGORIES.contains(reason)) {
            return "class." + reason;
        }
        if (SIZE.contains(reason)) {
            return "reason.size";
        }
        if (reason.equals("FINDING_LIMIT")) {
            return "reason.findings";
        }
        if (ENCODED.contains(reason)) {
            return "reason.encoded";
        }
        if (FORMAT.contains(reason)) {
            return "reason.format";
        }
        if (INCOMPLETE.contains(reason)) {
            return "reason.incomplete";
        }
        return null;
    }

    static byte[] html(String reason, String platform, String ref) {
        return html(PAGES, reason, platform, ref);
    }

    static byte[] html(EndUserPages pages, String reason, String platform, String ref) {
        String label = pages.label(labelKeyOrOther(reason));
        return pages.blockHtml(kind(reason), label, platform == null ? "bilinmeyen" : platform, safeRef(ref))
            .getBytes(StandardCharsets.UTF_8);
    }

    static byte[] json(String reason, String ref) {
        return ("{\"error\":{\"type\":\"rwsafe_blocked\",\"reason\":\"" + jsonSafe(reason == null ? "policy" : reason)
            + "\",\"message\":" + jsonString(PAGES.apiMessage(kind(reason))) + ",\"ref\":\"" + safeRef(ref) + "\"}}")
            .getBytes(StandardCharsets.UTF_8);
    }

    /** The coaching page after a WARN verdict, for the out-of-band coaching surface. */
    static byte[] coachingHtml(String reason, String ref) {
        return PAGES.coachingHtml(PAGES.label(labelKeyOrOther(reason)), safeRef(ref)).getBytes(StandardCharsets.UTF_8);
    }

    static byte[] sseTermination(String reason, String ref) {
        return ("event: error\ndata: {\"type\":\"rwsafe_stream_terminated\",\"reason\":\""
            + jsonSafe(reason == null ? "policy" : reason) + "\",\"message\":" + jsonString(PAGES.streamTerminatedText(streamLabel(reason), safeRef(ref)))
            + ",\"ref\":\"" + safeRef(ref) + "\"}\n\n").getBytes(StandardCharsets.UTF_8);
    }

    static byte[] terminatedText(String reason, String ref) {
        return (PAGES.streamTerminatedText(streamLabel(reason), safeRef(ref)) + "\n").getBytes(StandardCharsets.UTF_8);
    }

    private static String labelKeyOrOther(String reason) {
        String key = labelKey(reason);
        return key == null ? "class.other" : key;
    }

    /** The reference id as the employee may quote it: letters, digits and {@code -} only, at most 64. */
    static String safeRef(String ref) {
        String s = jsonSafe(ref == null ? "" : ref);
        if (s.isEmpty()) {
            return "-";
        }
        return s.length() > 64 ? s.substring(0, 64) : s;
    }

    private static String jsonSafe(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
                out.append(c);
            }
        }
        return out.toString();
    }

    /** A JSON string literal; markup characters are escaped too, so the message is inert wherever it is shown. */
    static String jsonString(String s) {
        StringBuilder out = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '<', '>', '&', '\'' -> unicodeEscape(out, c);
                default -> {
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                        unicodeEscape(out, c);
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    private static void unicodeEscape(StringBuilder out, char c) {
        String hex = "0123456789abcdef";
        out.append("\\u").append(hex.charAt((c >> 12) & 0xF)).append(hex.charAt((c >> 8) & 0xF))
            .append(hex.charAt((c >> 4) & 0xF)).append(hex.charAt(c & 0xF));
    }
}
