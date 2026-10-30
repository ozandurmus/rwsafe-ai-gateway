package io.rwsafe.dataplane.events;

/** Where request threads hand verdict events; implementations never block the caller. */
public interface EventSink {

    void emit(VerdictEvent event);

    /** True when the event path cannot take more: fail-closed flows then block (SR-DP-12, ADR-010 §3). */
    default boolean saturated() {
        return false;
    }
}
