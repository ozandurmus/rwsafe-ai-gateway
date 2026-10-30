package io.rwsafe.architecture.fixtures.content;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;

@BodyBearing
public final class PromptPrintingText {

    private final String text;

    public PromptPrintingText(String text) {
        this.text = text;
    }

    @BodyContent
    public String text() {
        return text;
    }

    @Override
    public String toString() {
        return "Prompt[" + text + "]";
    }
}
