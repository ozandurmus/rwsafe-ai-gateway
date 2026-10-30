package io.rwsafe.dataplane.icap;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** Encoders for every ICAP response the engine sends (ICAP spec §4.2 to §4.5). */
public final class IcapResponses {

    public static final String SERVICE = "rwsafe-ai-gateway/0.1";
    public static final int ADVERTISED_PREVIEW = 4096;
    public static final int MAX_CONNECTIONS = 1000;

    private static final byte[] CONTINUE = "ICAP/1.0 100 Continue\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LAST_CHUNK = "0\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

    private IcapResponses() {
    }

    public static byte[] continue100() {
        return CONTINUE.clone();
    }

    public static byte[] options(IcapRequest.Method serviceMethod, String isTag, boolean available) {
        if (!available) {
            return error(503, "Service Unavailable", isTag, false);
        }
        StringBuilder s = new StringBuilder("ICAP/1.0 200 OK\r\n")
            .append("Methods: ").append(serviceMethod.name()).append("\r\n")
            .append("Service: ").append(SERVICE).append("\r\n")
            .append("ISTag: ").append(isTag).append("\r\n")
            .append("Encapsulated: null-body=0\r\n")
            .append("Max-Connections: ").append(MAX_CONNECTIONS).append("\r\n")
            .append("Options-TTL: 300\r\n")
            .append("Preview: ").append(ADVERTISED_PREVIEW).append("\r\n")
            .append("Allow: 204\r\n")
            .append("Transfer-Preview: *\r\n");
        if (serviceMethod == IcapRequest.Method.RESPMOD) {
            s.append("Transfer-Ignore: jpg,jpeg,gif,png,webp,woff,woff2,mp4\r\n");
        }
        return s.append("\r\n").toString().getBytes(StandardCharsets.US_ASCII);
    }

    public static byte[] noContent(String isTag) {
        return ("ICAP/1.0 204 No Content\r\nISTag: " + isTag + "\r\nEncapsulated: null-body=0\r\n\r\n")
            .getBytes(StandardCharsets.US_ASCII);
    }

    public static byte[] error(int status, String reason, String isTag, boolean close) {
        return ("ICAP/1.0 " + status + " " + reason + "\r\nISTag: " + isTag + "\r\nEncapsulated: null-body=0\r\n"
            + (close ? "Connection: close\r\n" : "") + "\r\n").getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * A 200 carrying one encapsulated HTTP message: {@code hdrName} is {@code req-hdr} or {@code res-hdr}; a null body
     * becomes {@code null-body}.
     */
    public static byte[] modified(String isTag, String hdrName, byte[] httpHead, byte[] body, boolean close) {
        String bodyName = hdrName.equals("req-hdr") ? "req-body" : "res-body";
        ByteArrayOutputStream out = new ByteArrayOutputStream(httpHead.length + (body == null ? 0 : body.length) + 256);
        out.writeBytes(("ICAP/1.0 200 OK\r\nISTag: " + isTag + "\r\nEncapsulated: " + hdrName + "=0, "
            + (body == null ? "null-body=" : bodyName + "=") + httpHead.length + "\r\n"
            + (close ? "Connection: close\r\n" : "") + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(httpHead);
        if (body != null) {
            if (body.length > 0) {
                out.writeBytes(chunk(body, 0, body.length));
            }
            out.writeBytes(LAST_CHUNK);
        }
        return out.toByteArray();
    }

    /** The head of a streamed 200 RESPMOD answer; chunks and the last chunk follow separately. */
    public static byte[] streamedResponseHead(String isTag, byte[] httpResponseHead) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(httpResponseHead.length + 128);
        out.writeBytes(("ICAP/1.0 200 OK\r\nISTag: " + isTag + "\r\nEncapsulated: res-hdr=0, res-body="
            + httpResponseHead.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(httpResponseHead);
        return out.toByteArray();
    }

    public static byte[] chunk(byte[] data, int off, int len) {
        byte[] size = (Integer.toHexString(len) + "\r\n").getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[size.length + len + 2];
        System.arraycopy(size, 0, out, 0, size.length);
        System.arraycopy(data, off, out, size.length, len);
        out[out.length - 2] = '\r';
        out[out.length - 1] = '\n';
        return out;
    }

    /** The same ICAP message with {@code Connection: close} after its status line, for a draining engine (ICAP spec §7). */
    public static byte[] closing(byte[] message) {
        String head = new String(message, 0, Math.min(message.length, 4096), StandardCharsets.ISO_8859_1);
        int eol = head.indexOf("\r\n");
        int end = head.indexOf("\r\n\r\n");
        if (eol < 0 || (end >= 0 && head.substring(0, end).contains("\r\nConnection: close"))) {
            return message;
        }
        byte[] add = "Connection: close\r\n".getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[message.length + add.length];
        System.arraycopy(message, 0, out, 0, eol + 2);
        System.arraycopy(add, 0, out, eol + 2, add.length);
        System.arraycopy(message, eol + 2, out, eol + 2 + add.length, message.length - eol - 2);
        return out;
    }

    public static byte[] lastChunk() {
        return LAST_CHUNK.clone();
    }
}
