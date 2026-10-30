package io.rwsafe.detect;

import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import java.util.List;

/** Turkish national identity numbers: exactly eleven digits, first digit non-zero, both checksum digits valid. */
public final class TcknDetector implements Detector {

    @Override
    public void scan(String text, List<Finding> out) {
        int i = 0;
        int n = text.length();
        while (i < n) {
            if (!DigitRuns.isDigit(text.charAt(i))) {
                i++;
                continue;
            }
            int start = i;
            while (i < n && DigitRuns.isDigit(text.charAt(i))) {
                i++;
            }
            if (i - start == 11 && DigitRuns.boundaryBefore(text, start) && DigitRuns.boundaryAfter(text, i)
                && valid(text, start)) {
                if (out.size() >= DetectorSet.MAX_FINDINGS) {
                    return;
                }
                out.add(new Finding(DataClass.TCKN, start, i));
            }
        }
    }

    /** The two TCKN check digits over the eleven digits starting at {@code from}. */
    static boolean valid(CharSequence s, int from) {
        int[] d = new int[11];
        for (int k = 0; k < 11; k++) {
            d[k] = s.charAt(from + k) - '0';
        }
        if (d[0] == 0) {
            return false;
        }
        int odd = d[0] + d[2] + d[4] + d[6] + d[8];
        int even = d[1] + d[3] + d[5] + d[7];
        int tenth = Math.floorMod(odd * 7 - even, 10);
        int sum = 0;
        for (int k = 0; k < 10; k++) {
            sum += d[k];
        }
        return d[9] == tenth && d[10] == sum % 10;
    }
}
