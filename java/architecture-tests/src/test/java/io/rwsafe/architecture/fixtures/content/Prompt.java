package io.rwsafe.architecture.fixtures.content;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;

/** Compliant content type: its toString() prints a derived count only. */
@BodyBearing
public final class Prompt {

    private final String text;
    private final int length;

    public Prompt(String text) {
        this.text = text;
        this.length = text.length();
    }

    @BodyContent
    public String text() {
        return text;
    }

    @Override
    public String toString() {
        return "Prompt[length=" + length + "]";
    }
}
