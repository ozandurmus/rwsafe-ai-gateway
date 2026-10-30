package io.rwsafe.dataplane.boot;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import io.netty.util.concurrent.EventExecutorGroup;
import io.rwsafe.dataplane.server.IcapChannelInitializer;
import io.rwsafe.dataplane.server.IcapEngine;
import java.io.File;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLException;

/** Binds the ICAP listeners and owns their event loops (process wiring; never a request thread). */
public final class IcapServer implements AutoCloseable {

    /** ICAP spec §7: the whole drain window, of which the first part serves with Connection: close. */
    private static final long DRAIN_TOTAL_MILLIS = 20_000;

    private final IcapEngine engine;
    private final long drainServeMillis;
    private final EventLoopGroup boss = new NioEventLoopGroup(1);
    private final EventLoopGroup workers = new NioEventLoopGroup();
    private final EventExecutorGroup inspection =
        new DefaultEventExecutorGroup(Math.max(2, Runtime.getRuntime().availableProcessors()));
    private final List<Channel> channels = new ArrayList<>();

    public IcapServer(IcapEngine engine, long drainServeMillis) {
        this.engine = engine;
        this.drainServeMillis = drainServeMillis;
    }

    /** Plain ICAP (pilot exception H-2). Returns the bound port (useful with port 0 in tests). */
    public int start(String host, int port) throws InterruptedException {
        return bind(host, port, null);
    }

    /** Secure ICAP: TLS 1.2/1.3 with a client certificate chained to {@code clientCa} required (ICAP spec §2). */
    public int startSecure(String host, int port, File certChain, File privateKey, File clientCa)
        throws InterruptedException, SSLException {
        SslContext tls = SslContextBuilder.forServer(certChain, privateKey)
            .trustManager(clientCa)
            .clientAuth(ClientAuth.REQUIRE)
            .protocols("TLSv1.3", "TLSv1.2")
            .build();
        return bind(host, port, tls);
    }

    private int bind(String host, int port, SslContext tls) throws InterruptedException {
        ServerBootstrap b = new ServerBootstrap()
            .group(boss, workers)
            .channel(NioServerSocketChannel.class)
            .option(ChannelOption.SO_BACKLOG, 2000)
            .childOption(ChannelOption.TCP_NODELAY, true)
            .childOption(ChannelOption.SO_KEEPALIVE, true)
            .childHandler(new IcapChannelInitializer(engine, inspection, tls));
        Channel ch = b.bind(new InetSocketAddress(host, port)).sync().channel();
        channels.add(ch);
        return ((InetSocketAddress) ch.localAddress()).getPort();
    }

    public void awaitClose() throws InterruptedException {
        for (Channel ch : channels) {
            ch.closeFuture().sync();
        }
    }

    /**
     * Drains (ICAP spec §7): OPTIONS answers 503 at once; transactions are served with Connection: close for the serve
     * window; afterwards new ones get 503; the listeners close when nothing is in flight or the window ends.
     */
    @Override
    public void close() {
        engine.startDraining();
        long start = System.nanoTime();
        sleepUntil(start, drainServeMillis);
        long deadline = start + TimeUnit.MILLISECONDS.toNanos(Math.max(DRAIN_TOTAL_MILLIS, drainServeMillis));
        while (engine.admission().inflight() > 0 && System.nanoTime() < deadline) {
            sleepUntil(System.nanoTime(), 50);
        }
        for (Channel ch : channels) {
            ch.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
        }
        boss.shutdownGracefully(0, 2, TimeUnit.SECONDS);
        workers.shutdownGracefully(0, 5, TimeUnit.SECONDS);
        inspection.shutdownGracefully(0, 5, TimeUnit.SECONDS);
    }

    private static void sleepUntil(long startNanos, long millis) {
        long end = startNanos + TimeUnit.MILLISECONDS.toNanos(millis);
        long left;
        while ((left = end - System.nanoTime()) > 0) {
            try {
                Thread.sleep(Math.max(1, TimeUnit.NANOSECONDS.toMillis(left)));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }
}
