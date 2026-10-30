package io.rwsafe.architecture.fixtures.inline;

import java.util.regex.Pattern;

public final class JavaRegexInspector {

    private static final Pattern DIGITS = Pattern.compile("[0-9]+");

    public boolean inspect(String untrusted) {
        return DIGITS.matcher(untrusted).find();
    }
}
