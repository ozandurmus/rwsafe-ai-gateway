package io.rwsafe.platform.enduser;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * The {@code {{name}}} placeholders of the end-user catalogue. A hand-written scanner (no regular expression: this module
 * is on the inline path, SR-DP-1). Rendering escapes the literal text and every inserted value alike when the output is
 * HTML, so neither a catalogue edit nor a value can inject markup (SEC-5).
 */
final class Template {

    private static final int MAX_NAME = 32;

    private Template() {
    }

    /** The placeholder names of {@code text}, in order of first use; a malformed placeholder is refused. */
    static Set<String> placeholders(String text) {
        Set<String> names = new LinkedHashSet<>();
        int i = 0;
        while (true) {
            int open = text.indexOf("{{", i);
            if (open < 0) {
                return names;
            }
            int close = text.indexOf("}}", open + 2);
            if (close < 0) {
                throw new IllegalArgumentException("an unclosed placeholder at offset " + open);
            }
            names.add(name(text, open + 2, close));
            i = close + 2;
        }
    }

    /**
     * Fills every placeholder from {@code values}; a placeholder without a value is refused (the caller decides which
     * paragraphs it can render). {@code html} escapes literal text and values.
     */
    static String render(String text, Map<String, String> values, boolean html) {
        StringBuilder out = new StringBuilder(text.length() + 64);
        int i = 0;
        while (true) {
            int open = text.indexOf("{{", i);
            if (open < 0) {
                append(out, text.substring(i), html);
                return out.toString();
            }
            int close = text.indexOf("}}", open + 2);
            if (close < 0) {
                throw new IllegalArgumentException("an unclosed placeholder at offset " + open);
            }
            append(out, text.substring(i, open), html);
            String name = name(text, open + 2, close);
            String value = values.get(name);
            if (value == null) {
                throw new IllegalStateException("no value for the placeholder " + name);
            }
            append(out, value, html);
            i = close + 2;
        }
    }

    private static String name(String text, int from, int to) {
        if (to - from < 1 || to - from > MAX_NAME) {
            throw new IllegalArgumentException("a placeholder name has 1 to " + MAX_NAME + " characters");
        }
        for (int k = from; k < to; k++) {
            char c = text.charAt(k);
            if (!((c >= 'a' && c <= 'z') || c == '_')) {
                throw new IllegalArgumentException("a placeholder name is lower-case letters and underscores");
            }
        }
        return text.substring(from, to);
    }

    private static void append(StringBuilder out, String s, boolean html) {
        if (html) {
            Html.escape(out, s);
        } else {
            out.append(s);
        }
    }
}
