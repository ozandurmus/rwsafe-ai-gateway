package io.rwsafe.detect;

/** Helpers for the numeric validators: a candidate must not touch another digit or letter on either side. */
final class DigitRuns {

    private DigitRuns() {
    }

    static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    static boolean boundaryBefore(String text, int index) {
        return index == 0 || !Character.isLetterOrDigit(text.charAt(index - 1));
    }

    static boolean boundaryAfter(String text, int index) {
        return index >= text.length() || !Character.isLetterOrDigit(text.charAt(index));
    }
}
