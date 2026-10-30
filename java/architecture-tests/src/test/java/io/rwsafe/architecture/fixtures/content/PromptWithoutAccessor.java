package io.rwsafe.architecture.fixtures.content;

import io.rwsafe.platform.content.BodyBearing;

@BodyBearing
public final class PromptWithoutAccessor {

    private final String text;

    public PromptWithoutAccessor(String text) {
        this.text = text;
    }

    public int length() {
        return text.length();
    }

    @Override
    public String toString() {
        return "Prompt";
    }
}
