package io.rwsafe.policy;

/**
 * A classified transaction: platform × surface × step (ICAP spec §4.3). {@code platform} is a platform-matrix id or
 * {@code unknown}; values are vocabulary, never a host name of the estate.
 */
public record Flow(String platform, Surface surface, Step step) {

    public enum Surface { WEB, API, IDE, CLI, UNKNOWN }

    public enum Step { LOGIN, CHAT, UPLOAD, TOOL_CALL, OTHER }
}
