package io.rwsafe.architecture.fixtures.content;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;

@BodyBearing
public final class PromptWithoutToString {

    private final String text;

    public PromptWithoutToString(String text) {
        this.text = text;
    }

    @BodyContent
    public String text() {
        return text;
    }
}
