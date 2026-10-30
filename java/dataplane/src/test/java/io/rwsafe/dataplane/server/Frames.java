package io.rwsafe.dataplane.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/** Builds ICAP frames from the synthetic fixtures (test resources {@code fixtures/icap/...}). */
final class Frames {

    private Frames() {
    }

    /** An encapsulated HTTP request: head with CRLF line ends and the body bytes. */
    record Http(byte[] head, byte[] body) {
    }

    static Http fixture(String path, String prompt) {
        String text;
        try (InputStream in = Frames.class.getResourceAsStream("/fixtures/icap/" + path)) {
            if (in == null) {
                throw new IllegalArgumentException("no fixture " + path);
            }
            text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        int split = text.indexOf("\n\n");
        String head = text.substring(0, split + 1);
        String body = text.substring(split + 2).stripTrailing().replace("{{PROMPT}}", jsonEscape(prompt));
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        head = head.replace("{{LEN}}", Integer.toString(bodyBytes.length)).replace("\n", "\r\n") + "\r\n";
        return new Http(head.getBytes(StandardCharsets.ISO_8859_1), bodyBytes);
    }

    static Http http(String head, byte[] body) {
        return new Http((head.replace("\n", "\r\n") + "\r\n").getBytes(StandardCharsets.ISO_8859_1), body);
    }

    /**
     * A REQMOD frame. With {@code preview >= 0} only the first {@code preview} bytes are sent, terminated by
     * {@code 0; ieof} when they are the whole body; {@link #rest} gives the remainder after {@code 100 Continue}.
     */
    static byte[] reqmod(Http http, int preview, boolean allow204) {
        return frame("REQMOD", "/reqmod-ai", "req-hdr=0, req-body=" + http.head().length, http.head(), http.body(),
            preview, allow204, "");
    }

    static byte[] reqmodWithIdentity(Http http, String user, String clientIp) {
        return frame("REQMOD", "/reqmod-ai", "req-hdr=0, req-body=" + http.head().length, http.head(), http.body(),
            -1, true, "X-Authenticated-User: " + user + "\r\nX-Client-IP: " + clientIp + "\r\n");
    }

    /** A REQMOD frame with the proxy's group claim; {@code groups} null sends no {@code X-Authenticated-Groups}. */
    static byte[] reqmodWithGroups(Http http, String groups) {
        return frame("REQMOD", "/reqmod-ai", "req-hdr=0, req-body=" + http.head().length, http.head(), http.body(),
            -1, true, "X-Authenticated-User: synthetic-user\r\n"
                + (groups == null ? "" : "X-Authenticated-Groups: " + groups + "\r\n"));
    }

    static byte[] respmod(Http request, String responseHead, byte[] responseBody, int preview) {
        byte[] resHead = (responseHead.replace("\n", "\r\n") + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
        byte[] heads = new byte[request.head().length + resHead.length];
        System.arraycopy(request.head(), 0, heads, 0, request.head().length);
        System.arraycopy(resHead, 0, heads, request.head().length, resHead.length);
        String enc = "req-hdr=0, res-hdr=" + request.head().length + ", res-body=" + heads.length;
        return frame("RESPMOD", "/respmod-ai", enc, heads, responseBody, preview, true, "");
    }

    /** A RESPMOD frame without preview whose body is sent in ICAP chunks of exactly {@code chunkSize} bytes. */
    static byte[] respmodChunked(Http request, String responseHead, byte[] responseBody, int chunkSize) {
        byte[] resHead = (responseHead.replace("\n", "\r\n") + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String head = "RESPMOD icap://icap.example.invalid/respmod-ai ICAP/1.0\r\nHost: icap.example.invalid\r\n"
            + "Encapsulated: req-hdr=0, res-hdr=" + request.head().length + ", res-body="
            + (request.head().length + resHead.length) + "\r\nAllow: 204\r\n\r\n";
        out.writeBytes(head.getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(request.head());
        out.writeBytes(resHead);
        for (int off = 0; off < responseBody.length; off += chunkSize) {
            out.writeBytes(chunk(responseBody, off, Math.min(chunkSize, responseBody.length - off)));
        }
        out.writeBytes("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        return out.toByteArray();
    }

    static byte[] rest(byte[] body, int preview) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (body.length > preview) {
            out.writeBytes(chunk(body, preview, body.length - preview));
        }
        out.writeBytes("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        return out.toByteArray();
    }

    static byte[] options(String service) {
        return ("OPTIONS icap://icap.example.invalid" + service + " ICAP/1.0\r\nHost: icap.example.invalid\r\n\r\n")
            .getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] frame(String method, String service, String encapsulated, byte[] heads, byte[] body,
                                int preview, boolean allow204, String extraHeaders) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StringBuilder h = new StringBuilder(method).append(" icap://icap.example.invalid").append(service)
            .append(" ICAP/1.0\r\nHost: icap.example.invalid\r\nEncapsulated: ").append(encapsulated).append("\r\n");
        if (allow204) {
            h.append("Allow: 204\r\n");
        }
        if (preview >= 0) {
            h.append("Preview: ").append(preview).append("\r\n");
        }
        h.append(extraHeaders).append("\r\n");
        out.writeBytes(h.toString().getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(heads);
        if (preview < 0) {
            if (body.length > 0) {
                out.writeBytes(chunk(body, 0, body.length));
            }
            out.writeBytes("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        } else {
            int n = Math.min(preview, body.length);
            if (n > 0) {
                out.writeBytes(chunk(body, 0, n));
            }
            out.writeBytes((body.length <= preview ? "0; ieof\r\n\r\n" : "0\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        }
        return out.toByteArray();
    }

    static byte[] chunk(byte[] data, int off, int len) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes((Integer.toHexString(len) + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(data, off, len);
        out.writeBytes("\r\n".getBytes(StandardCharsets.US_ASCII));
        return out.toByteArray();
    }

    private static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
