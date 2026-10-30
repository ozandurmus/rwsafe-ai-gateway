package io.rwsafe.control.support;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * A minimal blocking ICAP client for the log-scanner test (the data plane's own test client is not on this classpath):
 * builds REQMOD and RESPMOD frames over synthetic HTTP messages and reads one response, keeping its text for the scan.
 */
public final class IcapClient implements AutoCloseable {

    /** One ICAP response: status and every byte the data plane sent back, as text. */
    public record Response(int status, String text) {
    }

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;

    public IcapClient(int port) throws IOException {
        socket = new Socket("127.0.0.1", port);
        socket.setSoTimeout(10_000);
        in = socket.getInputStream();
        out = socket.getOutputStream();
    }

    /** A REQMOD frame without preview; {@code icapHeaders} are extra ICAP header lines ending in CRLF. */
    public static byte[] reqmod(String httpHead, byte[] body, String icapHeaders) {
        byte[] head = crlf(httpHead);
        return frame("REQMOD", "/reqmod-ai", "req-hdr=0, req-body=" + head.length, head, body, icapHeaders);
    }

    /** A RESPMOD frame without preview over {@code requestHead} and {@code responseHead}. */
    public static byte[] respmod(String requestHead, String responseHead, byte[] body) {
        byte[] req = crlf(requestHead);
        byte[] res = crlf(responseHead);
        byte[] heads = new byte[req.length + res.length];
        System.arraycopy(req, 0, heads, 0, req.length);
        System.arraycopy(res, 0, heads, req.length, res.length);
        return frame("RESPMOD", "/respmod-ai", "req-hdr=0, res-hdr=" + req.length + ", res-body=" + heads.length, heads,
            body, "");
    }

    public static byte[] chunk(byte[] data) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes((Integer.toHexString(data.length) + "\r\n").getBytes(StandardCharsets.US_ASCII));
        b.writeBytes(data);
        b.writeBytes("\r\n".getBytes(StandardCharsets.US_ASCII));
        return b.toByteArray();
    }

    private static byte[] frame(String method, String service, String encapsulated, byte[] heads, byte[] body,
                                String icapHeaders) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        String head = method + " icap://icap.example.invalid" + service + " ICAP/1.0\r\nHost: icap.example.invalid\r\n"
            + "Encapsulated: " + encapsulated + "\r\nAllow: 204\r\n" + icapHeaders + "\r\n";
        b.writeBytes(head.getBytes(StandardCharsets.UTF_8));
        b.writeBytes(heads);
        if (body.length > 0) {
            b.writeBytes(chunk(body));
        }
        b.writeBytes("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        return b.toByteArray();
    }

    private static byte[] crlf(String head) {
        return (head.replace("\n", "\r\n") + "\r\n").getBytes(StandardCharsets.UTF_8);
    }

    /** Sends {@code frame} and reads one response; a connection the server closes yields what it sent first. */
    public Response exchange(byte[] frame) throws IOException {
        out.write(frame);
        out.flush();
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        String head = readHead(all);
        if (head == null) {
            return new Response(-1, all.toString(StandardCharsets.UTF_8));
        }
        int status = Integer.parseInt(head.substring(9, 12));
        String encapsulated = null;
        for (String line : head.split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("encapsulated:")) {
                encapsulated = line.substring(13).strip();
            }
        }
        if (encapsulated != null && !encapsulated.startsWith("null-body")) {
            String[] parts = encapsulated.split(",");
            String last = parts[parts.length - 1].strip();
            all.writeBytes(in.readNBytes(Integer.parseInt(last.substring(last.indexOf('=') + 1))));
            if (!last.startsWith("null-body")) {
                while (true) {
                    String size = readLine(all);
                    if (size == null) {
                        break;
                    }
                    int n = Integer.parseInt(size.split(";")[0].strip(), 16);
                    if (n == 0) {
                        readLine(all);
                        break;
                    }
                    all.writeBytes(in.readNBytes(n));
                    readLine(all);
                }
            }
        }
        return new Response(status, all.toString(StandardCharsets.UTF_8));
    }

    private String readHead(ByteArrayOutputStream all) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int state = 0;
        while (state < 4) {
            int c = in.read();
            if (c < 0) {
                all.writeBytes(b.toByteArray());
                return null;
            }
            b.write(c);
            state = (c == '\r' && (state == 0 || state == 2)) || (c == '\n' && (state == 1 || state == 3)) ? state + 1
                : (c == '\r' ? 1 : 0);
        }
        all.writeBytes(b.toByteArray());
        return b.toString(StandardCharsets.ISO_8859_1);
    }

    private String readLine(ByteArrayOutputStream all) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int prev = -1;
        while (true) {
            int c = in.read();
            if (c < 0) {
                all.writeBytes(b.toByteArray());
                return null;
            }
            b.write(c);
            if (prev == '\r' && c == '\n') {
                all.writeBytes(b.toByteArray());
                byte[] line = b.toByteArray();
                return new String(line, 0, line.length - 2, StandardCharsets.ISO_8859_1);
            }
            prev = c;
        }
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
