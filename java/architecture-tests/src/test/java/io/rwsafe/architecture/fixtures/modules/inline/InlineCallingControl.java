package io.rwsafe.architecture.fixtures.modules.inline;

import io.rwsafe.architecture.fixtures.modules.control.ControlService;

/** Violates the graph: the inline module depends on the control module. */
public final class InlineCallingControl {

    public String inspect() {
        return new ControlService().serve();
    }
}
