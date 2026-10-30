package io.rwsafe.control.capture;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;

/**
 * The optional {@code capture} object of one ingested verdict event (Q-4 b): the data plane's redacted text of a REDACT
 * verdict, whether its bound cut it, and the rewrite's size before the bound. Lives only in the request object until the
 * {@link CaptureSink} seals or drops it; printing it shows sizes only (AGENTS.md 4.14). Every field is required.
 */
@BodyBearing
public final class CapturedContent {

    private final String text;
    private final Boolean truncated;
    private final Long redactedBytes;

    @JsonCreator
    public CapturedContent(@JsonProperty(value = "text", required = true) String text,
                           @JsonProperty(value = "truncated", required = true) Boolean truncated,
                           @JsonProperty(value = "redactedBytes", required = true) Long redactedBytes) {
        this.text = text;
        this.truncated = truncated;
        this.redactedBytes = redactedBytes;
    }

    @BodyContent
    public String text() {
        return text;
    }

    public Boolean truncated() {
        return truncated;
    }

    public Long redactedBytes() {
        return redactedBytes;
    }

    @Override
    public String toString() {
        return "CapturedContent[truncated=" + truncated + ", redactedBytes=" + redactedBytes + "]";
    }
}
