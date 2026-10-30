package io.rwsafe.dataplane.events;

/** Where request threads hand verdict events; implementations never block the caller. */
public interface EventSink {

    void emit(VerdictEvent event);
}
