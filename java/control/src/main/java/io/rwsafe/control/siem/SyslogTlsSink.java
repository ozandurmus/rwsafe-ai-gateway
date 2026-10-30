package io.rwsafe.control.siem;

import io.rwsafe.control.siem.SiemDeliveryException.Reason;
import io.rwsafe.control.siem.SiemFormats.LineFormat;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * Syslog over TLS (RFC 5425) with CEF or LEEF payloads (SR-SIEM-3: TLS is the only transport this exporter has; there is
 * no UDP and no plain TCP code path). One long-lived connection (AGENTS.md section 14: one session, not a burst),
 * reopened after any failure. The server certificate must chain to the configured CA and match the configured host name.
 *
 * <p>RFC 5425 has no application acknowledgement: a batch counts as delivered when it is written and flushed. A receiver
 * never sends application data, so each connection has a watcher thread blocked in a read (JSSE reads and writes are
 * independent): end of stream or an error there means the receiver closed the connection, the next batch goes on a fresh
 * one, and when a batch had been flushed on the closed connection it is counted as possibly lost
 * ({@link #possiblyLostBatches}, Health and metrics; PO decision Q-SIEM-2: audit durability relies on HEC). No short
 * socket timeout is ever used on the TLS socket after the handshake (PR 23 review D-8). A write that the receiver does
 * not drain within the write timeout closes the TCP socket underneath (a watchdog), so the sender thread never hangs.
 */
public final class SyslogTlsSink implements SiemSink {

    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "rwsafe-siem-syslog-watchdog");
        t.setDaemon(true);
        return t;
    });

    private final String host;
    private final int port;
    private final LineFormat format;
    private final SSLContext tls;
    private final String hostname;
    private final int facility;
    private final String productVersion;
    private final Duration connectTimeout;
    private final Duration writeTimeout;
    private final AtomicLong possiblyLost = new AtomicLong();
    /** Written by the sender thread, read by {@link #close} from the stopping thread. */
    private volatile Connection connection;
    /** Set by {@link #close} (the sink is shut down): a connection opened afterwards is closed at once (D-12). */
    private volatile boolean shutdown;

    /**
     * One TLS connection, its TCP socket and its watcher.
     *
     * <p>Possibly-lost counting (Q-SIEM-2, PR 23 confirmation review D-12) is once per connection and cannot miss the
     * first batch: the sender sets {@code acknowledged} after a flush and then reads {@code peerClosed}; the watcher sets
     * {@code peerClosed} and then reads {@code acknowledged}. Both are volatile, so at least one side sees the other's
     * write and counts; {@code counted} keeps it to one.
     */
    private final class Connection {
        final SSLSocket ssl;
        final Socket raw;
        final OutputStream out;
        final AtomicBoolean counted = new AtomicBoolean();
        volatile boolean peerClosed;
        volatile boolean closing;
        volatile boolean acknowledged;

        Connection(SSLSocket ssl, Socket raw) throws IOException {
            this.ssl = ssl;
            this.raw = raw;
            this.out = new BufferedOutputStream(ssl.getOutputStream(), 64 * 1024);
            Thread watcher = new Thread(this::watch, "rwsafe-siem-syslog-watcher");
            watcher.setDaemon(true);
            watcher.start();
        }

        private void watch() {
            try {
                InputStream in = ssl.getInputStream();
                while (in.read() >= 0) {
                    // RFC 5425 receivers send nothing; anything read is ignored
                }
            } catch (IOException e) {
                // reset, alert or our own close
            } finally {
                if (!closing) {
                    peerClosed = true;
                    if (acknowledged) {
                        countLossOnce();
                    }
                }
            }
        }

        /** A batch reported delivered on this connection may not have been read by the receiver. */
        void countLossOnce() {
            if (counted.compareAndSet(false, true)) {
                possiblyLost.incrementAndGet();
            }
        }

        /**
         * Gracefully: the TLS socket first (close_notify), then the TCP socket, under a guard so a stalled peer cannot
         * hold the close. After a write error or a peer close only the TCP socket is closed.
         */
        void close(boolean graceful) {
            closing = true;
            if (graceful && !peerClosed) {
                ScheduledFuture<?> guard = WATCHDOG.schedule(() -> closeQuietly(raw), writeTimeout.toMillis(),
                    TimeUnit.MILLISECONDS);
                closeQuietly(ssl);
                guard.cancel(false);
            }
            closeQuietly(raw);
        }
    }

    public SyslogTlsSink(String host, int port, LineFormat format, SSLContext tls, String hostname, int facility,
                         String productVersion, Duration connectTimeout, Duration writeTimeout) {
        this.host = host;
        this.port = port;
        this.format = format;
        this.tls = tls;
        this.hostname = hostname;
        this.facility = facility;
        this.productVersion = productVersion;
        this.connectTimeout = connectTimeout;
        this.writeTimeout = writeTimeout;
    }

    @Override
    public String destination() {
        return "syslog";
    }

    @Override
    public long possiblyLostBatches() {
        return possiblyLost.get();
    }

    @Override
    public void deliver(List<SiemRecord> batch) throws SiemDeliveryException {
        Connection c = connection;
        if (c != null && c.peerClosed) {
            if (c.acknowledged) {
                c.countLossOnce();
            }
            c.close(false);
            connection = null;
            c = null;
        }
        if (c == null) {
            c = connect();
            connection = c;
            if (shutdown) {
                // close() ran while this thread was connecting: never leave a socket and a watcher behind.
                c.close(false);
                connection = null;
                throw new SiemDeliveryException(Reason.IO, "the syslog sink is shut down");
            }
        }
        Connection current = c;
        ScheduledFuture<?> watchdog = WATCHDOG.schedule(() -> closeQuietly(current.raw), writeTimeout.toMillis(),
            TimeUnit.MILLISECONDS);
        try {
            for (SiemRecord r : batch) {
                c.out.write(SyslogFrame.frame(facility, r.syslogSeverity(), r.time(), hostname,
                    r.stream().name().toLowerCase(Locale.ROOT), SiemFormats.line(format, r, productVersion)));
            }
            c.out.flush();
        } catch (IOException e) {
            // Classify before closing: a slow close must not turn an I/O failure into a timeout.
            boolean timedOut = watchdog.isDone();
            watchdog.cancel(false);
            if (c.acknowledged) {
                c.countLossOnce(); // an earlier batch on this broken connection may not have been read
            }
            c.close(false);
            connection = null;
            if (timedOut) {
                throw new SiemDeliveryException(Reason.TIMEOUT, "the syslog receiver did not drain within the write timeout");
            }
            throw new SiemDeliveryException(Reason.IO, "the syslog connection failed while writing");
        } finally {
            watchdog.cancel(false);
        }
        c.acknowledged = true;
        if (c.peerClosed) {
            c.countLossOnce(); // the receiver closed while or right after this batch was flushed
        }
    }

    private Connection connect() throws SiemDeliveryException {
        Socket s = null;
        try {
            s = new Socket();
            s.connect(new InetSocketAddress(host, port), (int) connectTimeout.toMillis());
            // TLS is layered over the connected TCP socket with the configured name, so SNI and the host-name check are
            // bound to that name (the connect itself honours the connect timeout).
            SSLSocket layered = (SSLSocket) tls.getSocketFactory().createSocket(s, host, port, true);
            SSLParameters p = layered.getSSLParameters();
            p.setEndpointIdentificationAlgorithm("HTTPS");
            p.setProtocols(SiemTls.PROTOCOLS);
            layered.setSSLParameters(p);
            layered.setSoTimeout((int) connectTimeout.toMillis());
            layered.startHandshake();
            // The watcher blocks in a read for the connection's life: no read timeout after the handshake.
            layered.setSoTimeout(0);
            return new Connection(layered, s);
        } catch (SSLException e) {
            closeQuietly(s);
            throw new SiemDeliveryException(Reason.TLS, "the syslog receiver's TLS handshake failed");
        } catch (SocketTimeoutException e) {
            closeQuietly(s);
            throw new SiemDeliveryException(Reason.TIMEOUT, "the syslog receiver did not answer in time");
        } catch (IOException e) {
            closeQuietly(s);
            throw new SiemDeliveryException(Reason.CONNECT, "the syslog receiver cannot be reached");
        }
    }

    /** Shuts the sink down: closes the open connection, and any connection a racing deliver opens after this. */
    @Override
    public void close() {
        shutdown = true;
        Connection c = connection;
        if (c != null) {
            connection = null;
            c.close(true);
        }
    }

    private static void closeQuietly(Socket s) {
        if (s == null) {
            return;
        }
        try {
            s.close();
        } catch (IOException ignored) {
            // closing a failed connection
        }
    }

    @Override
    public String toString() {
        return "SyslogTlsSink[" + format + "]";
    }
}
