package io.rwsafe.architecture.fixtures.content;

public final class PrintingReader {

    public void read(Prompt prompt) {
        System.out.println(prompt.text());
    }
}
