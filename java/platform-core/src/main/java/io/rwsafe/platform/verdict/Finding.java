package io.rwsafe.platform.verdict;

/**
 * One detector hit: the class and the half-open character range {@code [start, end)} in the normalised text it was found
 * in. It never carries the matched value (ADR-009: findings are class, offset and digest).
 */
public record Finding(DataClass dataClass, int start, int end) {

    public Finding {
        if (dataClass == null || start < 0 || end <= start) {
            throw new IllegalArgumentException("a finding needs a class and a non-empty range");
        }
    }
}
