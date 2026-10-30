package io.rwsafe.persistence;

/** One C6 finding class of an event and how often it was hit; never a value. */
public record FindingCount(String dataClass, int count) {
}
