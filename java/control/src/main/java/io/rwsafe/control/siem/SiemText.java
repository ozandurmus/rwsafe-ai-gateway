package io.rwsafe.control.siem;

/**
 * SR-SIEM-1: every exported string is stripped of control characters and length-capped before it reaches a format.
 * Removed: ANSI/ECMA-48 escape sequences as a whole (CSI, OSC, DCS, SOS, PM, APC and the two-character escapes, in their
 * 7-bit ESC form and their C1 form, so no {@code [31m} residue is left), then every C0 and C1 control (CR, LF, TAB, NUL,
 * DEL included), Unicode format characters (bidi overrides, zero-width characters, the byte-order mark), the line and
 * paragraph separators and unpaired surrogates.
 *
 * <p>Sequences are bounded (PR 23 review D-7): a control string without its terminator within {@value #MAX_STRING}
 * characters, or a control sequence without its final byte within {@value #MAX_CSI}, loses only its introducer, never the
 * rest of the field. Hand-written and linear: no regular expression runs over exported text.
 */
public final class SiemText {

    static final int MAX_STRING = 256;
    static final int MAX_CSI = 32;
    private static final int ESC = 0x1B;
    private static final int C1_DCS = 0x90;
    private static final int C1_SOS = 0x98;
    private static final int C1_CSI = 0x9B;
    private static final int C1_OSC = 0x9D;
    private static final int C1_PM = 0x9E;
    private static final int C1_APC = 0x9F;

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
            if (cp == C1_OSC || cp == C1_DCS || cp == C1_SOS || cp == C1_PM || cp == C1_APC) {
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
        // nF and Fp/Fe/Fs escapes: intermediates 0x20-0x2F, then one final 0x30-0x7E; bounded like a CSI.
        int k = i;
        while (k < s.length() && k - i < MAX_CSI && s.charAt(k) >= 0x20 && s.charAt(k) <= 0x2F) {
            k++;
        }
        if (k < s.length() && s.charAt(k) >= 0x30 && s.charAt(k) <= 0x7E) {
            return k + 1;
        }
        return i;
    }

    /**
     * Control sequence: parameters and intermediates 0x20-0x3F, one final byte 0x40-0x7E. Without a final byte within
     * {@link #MAX_CSI} characters only the introducer is removed.
     */
    private static int afterCsi(String s, int i) {
        int k = i;
        while (k < s.length() && k - i < MAX_CSI && s.charAt(k) >= 0x20 && s.charAt(k) <= 0x3F) {
            k++;
        }
        if (k < s.length() && s.charAt(k) >= 0x40 && s.charAt(k) <= 0x7E) {
            return k + 1;
        }
        return i;
    }

    /**
     * OSC, DCS, SOS, PM and APC strings run to BEL or the string terminator (ESC backslash or 0x9C). Without a terminator
     * within {@link #MAX_STRING} characters only the introducer is removed and the rest stays (cleaned) text.
     */
    private static int afterString(String s, int i) {
        int end = Math.min(s.length(), i + MAX_STRING);
        for (int k = i; k < end; k++) {
            char c = s.charAt(k);
            if (c == 0x07 || c == 0x9C) {
                return k + 1;
            }
            if (c == ESC && k + 1 < s.length() && s.charAt(k + 1) == '\\') {
                return k + 2;
            }
        }
        return i;
    }
}
