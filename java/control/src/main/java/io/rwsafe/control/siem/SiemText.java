package io.rwsafe.control.siem;

/**
 * SR-SIEM-1: every exported string is stripped of control characters and length-capped before it reaches a format.
 * Removed: ANSI/ECMA-48 escape sequences as a whole (CSI, OSC, DCS and the two-character escapes, so no {@code [31m}
 * residue is left), then every C0 and C1 control (CR, LF, TAB, NUL, DEL included), Unicode format characters (bidi
 * overrides, zero-width characters, the byte-order mark), the line and paragraph separators and unpaired surrogates.
 * Hand-written and linear: no regular expression runs over exported text.
 */
public final class SiemText {

    private static final int ESC = 0x1B;
    private static final int C1_CSI = 0x9B;
    private static final int C1_OSC = 0x9D;

    private SiemText() {
    }

    /** The cleaned text, at most {@code max} UTF-16 units, never splitting a surrogate pair; null stays null. */
    public static String clean(String s, int max) {
        if (s == null) {
            return null;
        }
        StringBuilder out = new StringBuilder(Math.min(s.length(), max));
        int n = s.length();
        int i = 0;
        while (i < n) {
            int cp = s.codePointAt(i);
            if (cp == ESC) {
                i = afterEscape(s, i + 1);
                continue;
            }
            if (cp == C1_CSI) {
                i = afterCsi(s, i + 1);
                continue;
            }
            if (cp == C1_OSC) {
                i = afterString(s, i + 1);
                continue;
            }
            i += Character.charCount(cp);
            if (dropped(cp)) {
                continue;
            }
            if (out.length() + Character.charCount(cp) > max) {
                break;
            }
            out.appendCodePoint(cp);
        }
        return out.toString();
    }

    static boolean dropped(int cp) {
        int type = Character.getType(cp);
        return type == Character.CONTROL || type == Character.FORMAT || type == Character.LINE_SEPARATOR
            || type == Character.PARAGRAPH_SEPARATOR || type == Character.SURROGATE;
    }

    /** {@code i} is just after ESC: skips the rest of the escape sequence. */
    private static int afterEscape(String s, int i) {
        if (i >= s.length()) {
            return i;
        }
        char c = s.charAt(i);
        if (c == '[') {
            return afterCsi(s, i + 1);
        }
        if (c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_') {
            return afterString(s, i + 1);
        }
        // nF and Fp/Fe/Fs escapes: intermediates 0x20-0x2F, then one final 0x30-0x7E.
        while (i < s.length() && s.charAt(i) >= 0x20 && s.charAt(i) <= 0x2F) {
            i++;
        }
        if (i < s.length() && s.charAt(i) >= 0x30 && s.charAt(i) <= 0x7E) {
            i++;
        }
        return i;
    }

    /** Control sequence: parameters 0x30-0x3F, intermediates 0x20-0x2F, one final byte 0x40-0x7E. */
    private static int afterCsi(String s, int i) {
        while (i < s.length() && s.charAt(i) >= 0x20 && s.charAt(i) <= 0x3F) {
            i++;
        }
        if (i < s.length() && s.charAt(i) >= 0x40 && s.charAt(i) <= 0x7E) {
            i++;
        }
        return i;
    }

    /** OSC, DCS, SOS, PM and APC strings run to BEL or the string terminator (ESC backslash or 0x9C). */
    private static int afterString(String s, int i) {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == 0x07 || c == 0x9C) {
                return i + 1;
            }
            if (c == ESC && i + 1 < s.length() && s.charAt(i + 1) == '\\') {
                return i + 2;
            }
            i++;
        }
        return i;
    }
}
