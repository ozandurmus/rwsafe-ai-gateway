package io.rwsafe.architecture.fixtures.inline;

import java.util.function.BiPredicate;

public final class StringMatchesReferenceInspector {

    public boolean inspect(String untrusted) {
        BiPredicate<String, String> matches = String::matches;
        return matches.test(untrusted, "(a+)+b");
    }
}
