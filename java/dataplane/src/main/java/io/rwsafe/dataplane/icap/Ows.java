package io.rwsafe.dataplane.icap;

/**
 * HTTP optional whitespace handling (RFC 9110 §5.6.3): only SP and HTAB are trimmed. {@code String.strip} would also
 * remove other control characters and make the engine read a token its peer does not (PR 11 review D-09).
 */
public final class Ows {

    private Ows() {
    }

    public static String trim(String s) {
        int a = 0;
        int b = s.length();
        while (a < b && (s.charAt(a) == ' ' || s.charAt(a) == '\t')) {
            a++;
        }
        while (b > a && (s.charAt(b - 1) == ' ' || s.charAt(b - 1) == '\t')) {
            b--;
        }
        return s.substring(a, b);
    }

    /** True when {@code s} holds a control character other than HTAB, or DEL. */
    public static boolean hasControl(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c < 0x20 && c != '\t') || c == 0x7f) {
                return true;
            }
        }
        return false;
    }
}
