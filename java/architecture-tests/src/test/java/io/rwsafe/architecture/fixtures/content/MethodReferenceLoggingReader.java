package io.rwsafe.architecture.fixtures.content;

import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class MethodReferenceLoggingReader {

    private static final Logger LOG = LoggerFactory.getLogger(MethodReferenceLoggingReader.class);

    public void read(Prompt prompt) {
        Function<Prompt, String> content = Prompt::text;
        LOG.info("prompt {}", content.apply(prompt));
    }
}
