package io.rwsafe.policy;

/** What the engine does with a transaction (AGENTS.md section 6: allow, warn, redact, block). */
public enum Action {
    ALLOW,
    WARN,
    REDACT,
    BLOCK;

    /** The stricter of two actions. */
    public Action max(Action other) {
        return other.ordinal() > ordinal() ? other : this;
    }
}
