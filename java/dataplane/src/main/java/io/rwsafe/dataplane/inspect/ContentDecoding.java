package io.rwsafe.dataplane.inspect;

import io.rwsafe.dataplane.icap.Ows;
import io.rwsafe.dataplane.icap.Tokens;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * One declared {@code Content-Encoding} layer of gzip or deflate, decoded in memory with the JDK {@link Inflater}
 * (BY-PROTO-7, ICAP spec §3). The output is bounded by the caller's cap (8x the input and the body limit); a stacked
 * coding, {@code br}, any other coding, a truncated or trailing-garbage stream, a multi-member gzip and an output over the
 * cap all answer null, which the inspector turns into {@code UNINSPECTABLE(ENCODED)}. Nothing is guessed from magic bytes:
 * an undeclared compressed body stays {@code BINARY}.
 */
final class ContentDecoding {

    /** Decompression ratio bound (ICAP spec §3). */
    static final int MAX_RATIO = 8;

    private static final int CHUNK = 8192;

    private ContentDecoding() {
    }

    /** The decoded body, or null when the coding is not one single gzip or deflate layer or breaks a bound. */
    static byte[] decode(String contentEncoding, byte[] b, int len, int maxOut) {
        List<String> codings = new ArrayList<>();
        for (String token : Tokens.split(contentEncoding, ',')) {
            String t = Ows.trim(token).toLowerCase(Locale.ROOT);
            if (!t.isEmpty()) {
                codings.add(t);
            }
        }
        if (codings.size() != 1) {
            return null;
        }
        try {
            return switch (codings.get(0)) {
                case "gzip", "x-gzip" -> gunzip(b, len, maxOut);
                case "deflate" -> inflate(b, len, maxOut);
                default -> null;
            };
        } catch (DataFormatException e) {
            return null;
        }
    }

    /**
     * gzip or zlib magic: a compressed layer inside a decoded one is a nested encoding. {@code 0x78 0x5e} is also the text
     * "x^", so it counts only when the bytes are not strict UTF-8 (PR 17 review D-04).
     */
    static boolean compressed(byte[] b, int len) {
        if (len < 2) {
            return false;
        }
        int b0 = b[0] & 0xff;
        int b1 = b[1] & 0xff;
        if (b0 == 0x1f && b1 == 0x8b) {
            return true;
        }
        if (b0 != 0x78) {
            return false;
        }
        return b1 == 0x01 || b1 == 0x9c || b1 == 0xda || (b1 == 0x5e && BodyInspector.strictUtf8(b, len) == null);
    }

    /** RFC 1952, one member: header, raw deflate, CRC-32 and ISIZE trailer, nothing after it. */
    private static byte[] gunzip(byte[] b, int len, int maxOut) throws DataFormatException {
        if (len < 18 || (b[0] & 0xff) != 0x1f || (b[1] & 0xff) != 0x8b || b[2] != 8) {
            return null;
        }
        int flags = b[3] & 0xff;
        if ((flags & 0xe0) != 0) {
            return null;
        }
        int p = 10;
        if ((flags & 0x04) != 0) {
            if (p + 2 > len) {
                return null;
            }
            p += 2 + ((b[p] & 0xff) | ((b[p + 1] & 0xff) << 8));
        }
        if ((flags & 0x08) != 0) {
            p = afterZero(b, p, len);
        }
        if (p >= 0 && (flags & 0x10) != 0) {
            p = afterZero(b, p, len);
        }
        if (p >= 0 && (flags & 0x02) != 0) {
            p += 2;
        }
        if (p < 0 || p > len - 8) {
            return null;
        }
        Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(b, p, len - p);
            byte[] out = drain(inflater, maxOut);
            if (out == null || inflater.getRemaining() != 8) {
                return null;
            }
            int t = len - 8;
            CRC32 crc = new CRC32();
            crc.update(out, 0, out.length);
            long expectedCrc = le32(b, t);
            long expectedSize = le32(b, t + 4);
            return crc.getValue() == expectedCrc && (out.length & 0xffffffffL) == expectedSize ? out : null;
        } finally {
            inflater.end();
        }
    }

    /** HTTP {@code deflate} is zlib (RFC 1950); a raw deflate stream (RFC 1951) is accepted too, as browsers do. */
    private static byte[] inflate(byte[] b, int len, int maxOut) throws DataFormatException {
        if (len < 2) {
            return null;
        }
        int cmf = b[0] & 0xff;
        boolean zlib = (cmf & 0x0f) == 8 && (cmf >> 4) <= 7 && ((cmf << 8) | (b[1] & 0xff)) % 31 == 0;
        Inflater inflater = new Inflater(!zlib);
        try {
            inflater.setInput(b, 0, len);
            byte[] out = drain(inflater, maxOut);
            return out != null && inflater.getRemaining() == 0 ? out : null;
        } finally {
            inflater.end();
        }
    }

    /** Inflates to the end of the stream; null when the stream is truncated, needs a dictionary or passes the cap. */
    private static byte[] drain(Inflater inflater, int maxOut) throws DataFormatException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(maxOut, 64 * 1024));
        byte[] chunk = new byte[CHUNK];
        int idle = 0;
        while (!inflater.finished()) {
            int n = inflater.inflate(chunk);
            if (n == 0 && (inflater.needsInput() || inflater.needsDictionary() || ++idle > 4)) {
                return null;
            }
            if ((long) out.size() + n > maxOut) {
                return null;
            }
            out.write(chunk, 0, n);
        }
        return out.toByteArray();
    }

    private static int afterZero(byte[] b, int from, int len) {
        for (int i = from; i < len; i++) {
            if (b[i] == 0) {
                return i + 1;
            }
        }
        return -1;
    }

    private static long le32(byte[] b, int at) {
        return (b[at] & 0xffL) | ((b[at + 1] & 0xffL) << 8) | ((b[at + 2] & 0xffL) << 16) | ((b[at + 3] & 0xffL) << 24);
    }
}
