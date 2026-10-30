package io.rwsafe.dataplane.server;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.concurrent.EventExecutorGroup;

/**
 * Pipeline of one ICAP connection: idle detection (inter-chunk and keep-alive, ICAP spec §3), then the connection handler
 * on the inspection executors, so content inspection never runs on the I/O event loop.
 */
public final class IcapChannelInitializer extends ChannelInitializer<SocketChannel> {

    private final IcapEngine engine;
    private final EventExecutorGroup inspection;

    public IcapChannelInitializer(IcapEngine engine, EventExecutorGroup inspection) {
        this.engine = engine;
        this.inspection = inspection;
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        ch.pipeline().addLast("idle", new IdleStateHandler(engine.config().streamIdleSeconds(), 0,
            engine.config().connectionIdleSeconds()));
        ch.pipeline().addLast(inspection, "icap", new IcapConnectionHandler(engine));
    }
}
