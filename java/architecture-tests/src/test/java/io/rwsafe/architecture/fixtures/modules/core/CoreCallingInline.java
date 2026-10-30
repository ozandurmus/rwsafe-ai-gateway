package io.rwsafe.architecture.fixtures.modules.core;

import io.rwsafe.architecture.fixtures.modules.inline.InlineInspector;

/** Violates the graph: the shared core reaches up into a module that depends on it. */
public final class CoreCallingInline {

    public String inspect() {
        return new InlineInspector().inspect();
    }
}
