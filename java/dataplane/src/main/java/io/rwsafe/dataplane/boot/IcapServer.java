package io.rwsafe.dataplane.boot;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import io.netty.util.concurrent.EventExecutorGroup;
import io.rwsafe.dataplane.server.IcapChannelInitializer;
import io.rwsafe.dataplane.server.IcapEngine;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

/** Binds the ICAP listener and owns its event loops (process wiring; never a request thread). */
public final class IcapServer implements AutoCloseable {

    private final IcapEngine engine;
    private final EventLoopGroup boss = new NioEventLoopGroup(1);
    private final EventLoopGroup workers = new NioEventLoopGroup();
    private final EventExecutorGroup inspection =
        new DefaultEventExecutorGroup(Math.max(2, Runtime.getRuntime().availableProcessors()));
    private Channel channel;

    public IcapServer(IcapEngine engine) {
        this.engine = engine;
    }

    /** Binds and returns the bound port (useful with port 0 in tests). */
    public int start(String host, int port) throws InterruptedException {
        ServerBootstrap b = new ServerBootstrap()
            .group(boss, workers)
            .channel(NioServerSocketChannel.class)
            .option(ChannelOption.SO_BACKLOG, 2000)
            .childOption(ChannelOption.TCP_NODELAY, true)
            .childOption(ChannelOption.SO_KEEPALIVE, true)
            .childHandler(new IcapChannelInitializer(engine, inspection));
        channel = b.bind(new InetSocketAddress(host, port)).sync().channel();
        return ((InetSocketAddress) channel.localAddress()).getPort();
    }

    public void awaitClose() throws InterruptedException {
        channel.closeFuture().sync();
    }

    @Override
    public void close() {
        engine.startDraining();
        if (channel != null) {
            channel.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
        }
        boss.shutdownGracefully(0, 2, TimeUnit.SECONDS);
        workers.shutdownGracefully(0, 5, TimeUnit.SECONDS);
        inspection.shutdownGracefully(0, 5, TimeUnit.SECONDS);
    }
}
