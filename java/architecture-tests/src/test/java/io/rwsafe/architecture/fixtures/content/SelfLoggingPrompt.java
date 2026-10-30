package io.rwsafe.architecture.fixtures.content;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@BodyBearing
public final class SelfLoggingPrompt {

    private static final Logger LOG = LoggerFactory.getLogger(SelfLoggingPrompt.class);

    private final String text;
    private final int length;

    public SelfLoggingPrompt(String text) {
        this.text = text;
        this.length = text.length();
        LOG.debug("created {}", text);
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
