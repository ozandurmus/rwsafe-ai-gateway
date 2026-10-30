package io.rwsafe.architecture.fixtures.content;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class LoggingReader {

    private static final Logger LOG = LoggerFactory.getLogger(LoggingReader.class);

    public void read(Prompt prompt) {
        LOG.info("prompt {}", prompt.text());
    }
}
