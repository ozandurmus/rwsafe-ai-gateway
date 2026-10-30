package io.rwsafe.control.siem;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

/**
 * A local RFC 5425 receiver for the tests: TLS on a loopback port, octet-counting frames parsed strictly (a frame whose
 * length prefix does not match fails the test through {@link #errors}). Every accepted connection is counted.
 */
final class TlsSyslogReceiver implements AutoCloseable {

    private final SSLServerSocket server;
    private final LinkedBlockingQueue<String> messages = new LinkedBlockingQueue<>();
    private final List<Socket> connections = new CopyOnWriteArrayList<>();
    final List<String> errors = new CopyOnWriteArrayList<>();
    final AtomicInteger accepted = new AtomicInteger();
    private final Thread acceptor;

    /** When set, connections complete the handshake and are then never read (a receiver that stopped draining). */
    volatile boolean stalled;

    TlsSyslogReceiver(SSLContext context) throws IOException {
        server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 16,
            InetAddress.getLoopbackAddress());
        acceptor = new Thread(this::acceptLoop, "test-syslog-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    int port() {
        return server.getLocalPort();
    }

    /** The next message (the SYSLOG-MSG without the length prefix), or null after the timeout. */
    String next(long millis) throws InterruptedException {
        return messages.poll(millis, TimeUnit.MILLISECONDS);
    }

    List<String> take(int n, long millis) throws InterruptedException {
        List<String> out = new ArrayList<>();
        long deadline = System.currentTimeMillis() + millis;
        while (out.size() < n && System.currentTimeMillis() < deadline) {
            String m = messages.poll(50, TimeUnit.MILLISECONDS);
            if (m != null) {
                out.add(m);
            }
        }
        return out;
    }

    /** Closes every open connection (a receiver restart); the listener stays up. */
    void dropConnections() throws IOException {
        for (Socket s : connections) {
            s.close();
        }
        connections.clear();
    }

    private void acceptLoop() {
        while (!server.isClosed()) {
            try {
                Socket s = server.accept();
                accepted.incrementAndGet();
                connections.add(s);
                Thread t = new Thread(() -> read(s), "test-syslog-connection");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                return;
            }
        }
    }

    private void read(Socket s) {
        if (stalled) {
            try {
                ((javax.net.ssl.SSLSocket) s).startHandshake();
            } catch (IOException e) {
                errors.add("handshake failed");
            }
            return;
        }
        try (InputStream in = new BufferedInputStream(s.getInputStream())) {
            while (true) {
                int length = 0;
                int digits = 0;
                int c;
                while ((c = in.read()) >= '0' && c <= '9') {
                    length = length * 10 + (c - '0');
                    digits++;
                }
                if (c < 0 && digits == 0) {
                    return;
                }
                if (c != ' ' || digits == 0) {
                    errors.add("bad frame prefix");
                    return;
                }
                ByteArrayOutputStream body = new ByteArrayOutputStream(length);
                for (int i = 0; i < length; i++) {
                    int b = in.read();
                    if (b < 0) {
                        errors.add("frame shorter than its length");
                        return;
                    }
                    body.write(b);
                }
                messages.add(body.toString(StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            // connection closed by a test or by the client
        }
    }

    @Override
    public void close() throws IOException {
        server.close();
        dropConnections();
    }
}
