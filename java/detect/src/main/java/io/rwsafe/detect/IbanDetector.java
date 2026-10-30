package io.rwsafe.detect;

import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import java.util.List;

/**
 * Turkish IBANs: {@code TR} (any case) plus 24 digits, written compact or in groups separated by single spaces, valid
 * under ISO 13616 mod-97. The range covers the IBAN as written, spaces included.
 */
public final class IbanDetector implements Detector {

    private static final int DIGITS = 24;

    @Override
    public void scan(String text, List<Finding> out) {
        int n = text.length();
        for (int i = 0; i + 1 < n; i++) {
            char t = text.charAt(i);
            char r = text.charAt(i + 1);
            if ((t != 'T' && t != 't') || (r != 'R' && r != 'r') || !DigitRuns.boundaryBefore(text, i)) {
                continue;
            }
            char[] digits = new char[DIGITS];
            int count = 0;
            int j = i + 2;
            while (j < n && count < DIGITS) {
                char c = text.charAt(j);
                if (DigitRuns.isDigit(c)) {
                    digits[count++] = c;
                    j++;
                } else if (c == ' ' && count > 0 && j + 1 < n && DigitRuns.isDigit(text.charAt(j + 1))) {
                    j++;
                } else {
                    break;
                }
            }
            if (count == DIGITS && DigitRuns.boundaryAfter(text, j) && valid(digits)) {
                if (out.size() >= DetectorSet.MAX_FINDINGS) {
                    return;
                }
                out.add(new Finding(DataClass.TR_IBAN, i, j));
                i = j - 1;
            }
        }
    }

    /** Mod-97 over the 24 digits followed by "TR" (2927) and the two check digits, which are the first two digits. */
    static boolean valid(char[] digits) {
        int rem = 0;
        for (int k = 2; k < DIGITS; k++) {
            rem = (rem * 10 + (digits[k] - '0')) % 97;
        }
        for (char c : new char[] {'2', '9', '2', '7', digits[0], digits[1]}) {
            rem = (rem * 10 + (c - '0')) % 97;
        }
        return rem == 1;
    }
}
