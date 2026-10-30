package io.rwsafe.architecture.fixtures.content;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;

/** Compliant content type: its toString() prints a String field that holds a digest, not content. */
@BodyBearing
public final class PromptWithDigest {

    private final String text;
    private final String digest;

    public PromptWithDigest(String text, String digest) {
        this.text = text;
        this.digest = digest;
    }

    @BodyContent
    public String text() {
        return text;
    }

    @Override
    public String toString() {
        return "Prompt[digest=" + digest + "]";
    }
}
