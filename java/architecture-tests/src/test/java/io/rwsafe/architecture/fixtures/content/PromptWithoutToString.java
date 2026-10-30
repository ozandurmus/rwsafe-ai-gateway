package io.rwsafe.architecture.fixtures.content;

import io.rwsafe.platform.content.BodyBearing;

@BodyBearing
public final class PromptWithoutToString {

    private final String text;

    public PromptWithoutToString(String text) {
        this.text = text;
    }

    public int length() {
        return text.length();
    }
}
