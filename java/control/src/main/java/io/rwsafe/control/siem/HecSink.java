package io.rwsafe.control.siem;

import io.rwsafe.control.siem.SiemDeliveryException.Reason;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

/**
 * Splunk HTTP Event Collector over HTTPS only (SR-SIEM-3; an {@code http:} URL is refused at construction). The token is
 * read from a mounted Secret file, sent only in the {@code Authorization: Splunk <token>} header, re-read after an
 * authentication failure (rotation), and never logged, printed or echoed. The server's answer body is discarded unread:
 * only its status code classifies the outcome.
 */
public final class HecSink implements SiemSink {

    /** The event endpoint when the configured URL has no path. */
    public static final String EVENT_PATH = "/services/collector/event";

    private final URI endpoint;
    private final Path tokenFile;
    private final String host;
    private final String index;
    private final Duration timeout;
    private final HttpClient client;
    private String token;

    public HecSink(String url, Path tokenFile, SSLContext tls, String host, String index, Duration timeout) {
        this.endpoint = endpoint(url);
        this.tokenFile = tokenFile;
        this.host = host;
        this.index = index == null || index.isBlank() ? null : index;
        this.timeout = timeout;
        SSLParameters p = new SSLParameters();
        p.setProtocols(SiemTls.PROTOCOLS);
        p.setEndpointIdentificationAlgorithm("HTTPS");
        this.client = HttpClient.newBuilder().sslContext(tls).sslParameters(p).connectTimeout(timeout)
            .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1).build();
        this.token = readToken(tokenFile);
    }

    /** {@code https://host[:port][/path]}; without a path, the event endpoint. Anything else is refused. */
    static URI endpoint(String url) {
        URI u;
        try {
            u = URI.create(url == null ? "" : url.strip());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("the HEC URL is not a URI");
        }
        if (!"https".equalsIgnoreCase(u.getScheme()) || u.getHost() == null || u.getRawUserInfo() != null
            || u.getRawQuery() != null || u.getRawFragment() != null) {
            throw new IllegalStateException("the HEC URL must be https://host[:port][/path] (SR-SIEM-3)");
        }
        String path = u.getRawPath() == null || u.getRawPath().isEmpty() || u.getRawPath().equals("/") ? EVENT_PATH
            : u.getRawPath();
        return URI.create("https://" + u.getRawAuthority() + path);
    }

    static String readToken(Path file) {
        try {
            String t = file == null ? "" : Files.readString(file, StandardCharsets.UTF_8).strip();
            if (t.isEmpty() || t.length() > 256 || !t.chars().allMatch(c -> c > 32 && c < 127)) {
                throw new IllegalStateException("the HEC token file is empty or malformed");
            }
            return t;
        } catch (IOException e) {
            throw new IllegalStateException("the HEC token file is missing");
        }
    }

    @Override
    public String destination() {
        return "hec";
    }

    @Override
    public void deliver(List<SiemRecord> batch) throws SiemDeliveryException {
        StringBuilder body = new StringBuilder(batch.size() * 512);
        for (SiemRecord r : batch) {
            body.append(SiemFormats.hec(r, host, index)).append('\n');
        }
        HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(timeout)
            .header("Authorization", "Splunk " + token)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8)).build();
        int status;
        try {
            status = client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
        } catch (HttpConnectTimeoutException e) {
            throw new SiemDeliveryException(Reason.CONNECT, "the HEC endpoint cannot be reached in time");
        } catch (HttpTimeoutException e) {
            throw new SiemDeliveryException(Reason.TIMEOUT, "the HEC endpoint did not answer in time");
        } catch (SSLException e) {
            throw new SiemDeliveryException(Reason.TLS, "the HEC endpoint's TLS handshake failed");
        } catch (IOException e) {
            throw new SiemDeliveryException(e.getCause() instanceof SSLException ? Reason.TLS : Reason.CONNECT,
                "the HEC request failed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SiemDeliveryException(Reason.IO, "the HEC request was interrupted");
        }
        if (status == 200) {
            return;
        }
        if (status == 401 || status == 403) {
            try {
                token = readToken(tokenFile);
            } catch (IllegalStateException keep) {
                // keep the previous token; the next attempt reports the same class
            }
            throw new SiemDeliveryException(Reason.AUTH, "the HEC endpoint refused the token");
        }
        if (status == 429 || status >= 500) {
            throw new SiemDeliveryException(Reason.UNAVAILABLE, "the HEC endpoint is busy or unavailable");
        }
        throw new SiemDeliveryException(Reason.REJECTED, "the HEC endpoint rejected the batch");
    }

    @Override
    public void close() {
        client.shutdownNow();
    }

    /** Never prints the token. */
    @Override
    public String toString() {
        return "HecSink[" + endpoint.getRawPath() + "]";
    }
}
