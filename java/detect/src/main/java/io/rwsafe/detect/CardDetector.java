package io.rwsafe.detect;

import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import java.util.List;

/**
 * Payment card numbers: 13 to 19 digits, optionally grouped by single spaces or hyphens, starting with 3, 4, 5 or 6, valid
 * under Luhn. The range covers the number as written.
 */
public final class CardDetector implements Detector {

    @Override
    public void scan(String text, List<Finding> out) {
        int n = text.length();
        int i = 0;
        int[] digits = new int[19];
        int[] ends = new int[19];
        while (i < n) {
            char first = text.charAt(i);
            if (first < '3' || first > '6' || !DigitRuns.boundaryBefore(text, i)) {
                i++;
                continue;
            }
            int count = 0;
            int j = i;
            while (j < n && count < 19) {
                char c = text.charAt(j);
                if (DigitRuns.isDigit(c)) {
                    digits[count] = c - '0';
                    ends[count++] = ++j;
                } else if ((c == ' ' || c == '-') && count > 0 && j + 1 < n && DigitRuns.isDigit(text.charAt(j + 1))) {
                    j++;
                } else {
                    break;
                }
            }
            // The longest valid candidate wins; trailing groups (expiry, CVV) do not hide the card (PR 11 review D-05).
            int found = -1;
            for (int len = count; len >= 13; len--) {
                if (DigitRuns.boundaryAfter(text, ends[len - 1]) && luhn(digits, len)) {
                    found = len;
                    break;
                }
            }
            if (found > 0) {
                if (out.size() >= DetectorSet.MAX_FINDINGS) {
                    return;
                }
                out.add(new Finding(DataClass.PAYMENT_CARD, i, ends[found - 1]));
                i = ends[found - 1];
            } else {
                i++;
            }
        }
    }

    static boolean luhn(int[] digits, int count) {
        int sum = 0;
        boolean dbl = false;
        for (int k = count - 1; k >= 0; k--) {
            int d = digits[k];
            if (dbl) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }
}
