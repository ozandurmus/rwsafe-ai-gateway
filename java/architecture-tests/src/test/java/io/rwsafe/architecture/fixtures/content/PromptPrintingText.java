package io.rwsafe.architecture.fixtures.content;

import io.rwsafe.platform.content.BodyBearing;

@BodyBearing
public final class PromptPrintingText {

    private final String text;

    public PromptPrintingText(String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return "Prompt[" + text + "]";
    }
}
