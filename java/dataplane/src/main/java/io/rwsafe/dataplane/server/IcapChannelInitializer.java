package io.rwsafe.dataplane.server;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.concurrent.EventExecutorGroup;

/**
 * Pipeline of one ICAP connection: TLS with a required client certificate on the Secure ICAP listener (ICAP spec §2),
 * idle detection (ICAP spec §3), then the connection handler on the inspection executors, so content inspection never
 * runs on the I/O event loop.
 */
public final class IcapChannelInitializer extends ChannelInitializer<SocketChannel> {

    private final IcapEngine engine;
    private final EventExecutorGroup inspection;
    private final SslContext tls;

    /** @param tls the Secure ICAP context (client authentication required), or null for the plain listener (H-2) */
    public IcapChannelInitializer(IcapEngine engine, EventExecutorGroup inspection, SslContext tls) {
        this.engine = engine;
        this.inspection = inspection;
        this.tls = tls;
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        if (tls != null) {
            ch.pipeline().addLast("tls", tls.newHandler(ch.alloc()));
        }
        ch.pipeline().addLast("idle", new IdleStateHandler(engine.config().streamIdleSeconds(), 0,
            engine.config().connectionIdleSeconds()));
        ch.pipeline().addLast(inspection, "icap", new IcapConnectionHandler(engine, tls != null));
    }
}
