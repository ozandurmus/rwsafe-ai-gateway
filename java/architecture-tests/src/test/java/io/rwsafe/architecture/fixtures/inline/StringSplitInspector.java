package io.rwsafe.architecture.fixtures.inline;

public final class StringSplitInspector {

    public int inspect(String untrusted) {
        return untrusted.split(",\\s*").length;
    }
}
