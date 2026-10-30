package io.rwsafe.architecture.fixtures.content;

import io.rwsafe.platform.content.BodyContent;

public final class StrayContentAccessor {

    private final String text;

    public StrayContentAccessor(String text) {
        this.text = text;
    }

    @BodyContent
    public String text() {
        return text;
    }
}
