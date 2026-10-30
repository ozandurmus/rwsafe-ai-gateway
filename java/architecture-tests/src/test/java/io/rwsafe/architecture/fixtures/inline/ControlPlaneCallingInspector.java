package io.rwsafe.architecture.fixtures.inline;

import io.rwsafe.architecture.fixtures.inline.controlplane.SnapshotClient;

public final class ControlPlaneCallingInspector {

    private final SnapshotClient client;

    public ControlPlaneCallingInspector(SnapshotClient client) {
        this.client = client;
    }

    public void inspect() {
        client.refresh();
    }
}
