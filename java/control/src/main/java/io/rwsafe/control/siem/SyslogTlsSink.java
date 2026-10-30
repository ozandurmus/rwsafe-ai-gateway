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
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * Syslog over TLS (RFC 5425) with CEF or LEEF payloads (SR-SIEM-3: TLS is the only transport this exporter has; there is
 * no UDP and no plain TCP code path). One long-lived connection (AGENTS.md section 14: one session, not a burst),
 * reopened after any failure. The server certificate must chain to the configured CA and match the configured host name.
 *
 * <p>RFC 5425 has no application acknowledgement: a batch counts as delivered when it is written and flushed. Before each
 * batch a zero-wait read detects a connection the receiver has closed, so the batch goes on a fresh connection instead of
 * into a dead one; a connection that dies after the flush can still lose that batch's bytes in flight (LOCAL_RUN.md "SIEM
 * export" names the residual; HEC confirms every batch with its HTTP answer). A write that the receiver does not drain
 * within the write timeout closes the connection (a watchdog), so the sender thread never hangs.
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
    private SSLSocket socket;
    /** The TCP socket under {@code socket}: the watchdog closes this one, which unblocks a write for certain. */
    private Socket raw;
    private OutputStream out;

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
    public void deliver(List<SiemRecord> batch) throws SiemDeliveryException {
        if (socket != null && peerClosed()) {
            close();
        }
        if (socket == null) {
            connect();
        }
        Socket current = raw;
        ScheduledFuture<?> watchdog = WATCHDOG.schedule(() -> closeQuietly(current), writeTimeout.toMillis(),
            TimeUnit.MILLISECONDS);
        try {
            for (SiemRecord r : batch) {
                out.write(SyslogFrame.frame(facility, r.syslogSeverity(), r.time(), hostname,
                    r.stream().name().toLowerCase(Locale.ROOT), SiemFormats.line(format, r, productVersion)));
            }
            out.flush();
        } catch (IOException e) {
            close();
            if (watchdog.isDone()) {
                throw new SiemDeliveryException(Reason.TIMEOUT, "the syslog receiver did not drain within the write timeout");
            }
            throw new SiemDeliveryException(Reason.IO, "the syslog connection failed while writing");
        } finally {
            watchdog.cancel(false);
        }
    }

    private void connect() throws SiemDeliveryException {
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
            socket = layered;
            raw = s;
            out = new BufferedOutputStream(layered.getOutputStream(), 64 * 1024);
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

    /** A receiver never sends on RFC 5425; end of stream (or an error) on a short read means the connection is gone. */
    private boolean peerClosed() {
        try {
            socket.setSoTimeout(1);
            InputStream in = socket.getInputStream();
            return in.read() < 0;
        } catch (SocketTimeoutException alive) {
            return false;
        } catch (IOException e) {
            return true;
        }
    }

    @Override
    public void close() {
        closeQuietly(raw);
        closeQuietly(socket);
        raw = null;
        socket = null;
        out = null;
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
