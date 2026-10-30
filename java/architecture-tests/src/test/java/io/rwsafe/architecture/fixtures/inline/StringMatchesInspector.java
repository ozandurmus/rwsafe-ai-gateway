package io.rwsafe.architecture.fixtures.inline;

public final class StringMatchesInspector {

    public boolean inspect(String untrusted) {
        return untrusted.matches("(a+)+b");
    }
}
