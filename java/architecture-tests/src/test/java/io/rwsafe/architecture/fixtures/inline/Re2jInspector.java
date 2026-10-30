package io.rwsafe.architecture.fixtures.inline;

import com.google.re2j.Pattern;

public final class Re2jInspector {

    private static final Pattern DIGITS = Pattern.compile("[0-9]+");

    public boolean inspect(String untrusted) {
        return DIGITS.matcher(untrusted).find();
    }
}
