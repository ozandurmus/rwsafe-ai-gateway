package io.rwsafe.dataplane.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** A minimal blocking ICAP client for tests: writes frames, reads one complete ICAP response at a time. */
final class IcapTestClient implements AutoCloseable {

    /** One ICAP response: status, head text, and the decoded encapsulated part (HTTP head + de-chunked body). */
    record Response(int status, String head, String httpHead, byte[] body) {
        String bodyText() {
            return new String(body, StandardCharsets.UTF_8);
        }

        String header(String name) {
            for (String line : head.split("\r\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 && line.substring(0, colon).equalsIgnoreCase(name)) {
                    return line.substring(colon + 1).strip();
                }
            }
            return null;
        }
    }

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;

    IcapTestClient(int port) throws IOException {
        this(new Socket("127.0.0.1", port));
    }

    /** Over an already connected socket (a TLS socket in the Secure ICAP tests). */
    IcapTestClient(Socket connected) throws IOException {
        socket = connected;
        socket.setSoTimeout(10_000);
        in = socket.getInputStream();
        out = socket.getOutputStream();
    }

    void write(byte[] bytes) throws IOException {
        out.write(bytes);
        out.flush();
    }

    Response read() throws IOException {
        String head = readHead();
        int status = Integer.parseInt(head.substring(9, 12));
        String encapsulated = null;
        for (String line : head.split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("encapsulated:")) {
                encapsulated = line.substring(13).strip();
            }
        }
        if (status == 100 || encapsulated == null || encapsulated.startsWith("null-body")) {
            return new Response(status, head, "", new byte[0]);
        }
        String[] parts = encapsulated.split(",");
        String last = parts[parts.length - 1].strip();
        int bodyOffset = Integer.parseInt(last.substring(last.indexOf('=') + 1));
        byte[] httpHead = in.readNBytes(bodyOffset);
        if (last.startsWith("null-body")) {
            return new Response(status, head, new String(httpHead, StandardCharsets.ISO_8859_1), new byte[0]);
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine();
            int size = Integer.parseInt(sizeLine.split(";")[0].strip(), 16);
            if (size == 0) {
                readLine();
                break;
            }
            body.write(in.readNBytes(size));
            readLine();
        }
        return new Response(status, head, new String(httpHead, StandardCharsets.ISO_8859_1), body.toByteArray());
    }

    /** True when the server closed the connection (read returns end of stream). */
    boolean closedByServer() throws IOException {
        return in.read() < 0;
    }

    private String readHead() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int state = 0;
        while (state < 4) {
            int c = in.read();
            if (c < 0) {
                throw new IOException("connection closed before a response head");
            }
            b.write(c);
            state = (c == '\r' && (state == 0 || state == 2)) || (c == '\n' && (state == 1 || state == 3)) ? state + 1
                : (c == '\r' ? 1 : 0);
        }
        return b.toString(StandardCharsets.ISO_8859_1);
    }

    private String readLine() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int prev = -1;
        while (true) {
            int c = in.read();
            if (c < 0) {
                throw new IOException("connection closed inside a chunk");
            }
            if (prev == '\r' && c == '\n') {
                byte[] all = b.toByteArray();
                return new String(all, 0, all.length - 1, StandardCharsets.ISO_8859_1);
            }
            b.write(c);
            prev = c;
        }
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
