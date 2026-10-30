package io.rwsafe.architecture.fixtures.content;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;

@BodyBearing
public final class PromptPrintingBytes {

    private final String text;
    private final byte[] raw;

    public PromptPrintingBytes(String text, byte[] raw) {
        this.text = text;
        this.raw = raw.clone();
    }

    @BodyContent
    public String text() {
        return text;
    }

    @Override
    public String toString() {
        return "Prompt[raw=" + raw.length + "]";
    }
}
