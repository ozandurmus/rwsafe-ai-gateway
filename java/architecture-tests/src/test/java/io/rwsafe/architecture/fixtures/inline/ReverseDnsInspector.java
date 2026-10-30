package io.rwsafe.architecture.fixtures.inline;

import java.net.InetAddress;

public final class ReverseDnsInspector {

    public String inspect(InetAddress client) {
        return client.getHostName();
    }
}
