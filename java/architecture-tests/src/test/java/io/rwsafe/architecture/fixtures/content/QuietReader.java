package io.rwsafe.architecture.fixtures.content;

/** Compliant reader: reads content and returns a derived count. */
public final class QuietReader {

    public int read(Prompt prompt) {
        return prompt.text().length();
    }
}
