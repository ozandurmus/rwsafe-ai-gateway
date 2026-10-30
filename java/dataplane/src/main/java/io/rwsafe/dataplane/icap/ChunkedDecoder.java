package io.rwsafe.dataplane.icap;

/**
 * Incremental decoder of the ICAP chunked body (RFC 3507 §4.5, RFC 9112 §7.1): feed bytes as they arrive; data goes to
 * the {@link Sink}; the zero-size chunk ends the body, with {@code ieof} recorded when the extension is present. Chunk
 * sizes above {@link #MAX_CHUNK} and size or trailer lines above 1 KiB are refused. Bytes after the end belong to the
 * next message and are not consumed.
 */
public final class ChunkedDecoder {

    public static final int MAX_CHUNK = 16 * 1024 * 1024;
    private static final int MAX_SIZE_LINE = 1024;
    private static final int MAX_TRAILER = 8 * 1024;

    /** Receives decoded data; must not retain {@code buf}. */
    public interface Sink {
        void data(byte[] buf, int off, int len);
    }

    private enum State { SIZE, DATA, DATA_CR, DATA_LF, TRAILER, DONE }

    private State state = State.SIZE;
    private final StringBuilder line = new StringBuilder();
    private int remaining;
    private boolean lastChunk;
    private boolean ieof;
    private int trailerBytes;
    private boolean trailerLineEmpty = true;
    private boolean sawCr;

    /** Consumes from {@code buf[off, off+len)}; returns the number of bytes consumed (less than len only at the end). */
    public int feed(byte[] buf, int off, int len, Sink sink) {
        int i = off;
        int end = off + len;
        while (i < end && state != State.DONE) {
            switch (state) {
                case SIZE -> {
                    byte b = buf[i++];
                    if (sawCr) {
                        if (b != '\n') {
                            throw new IcapProtocolException(400, "chunk size line not ended by CRLF");
                        }
                        sawCr = false;
                        sizeLineDone();
                    } else if (b == '\r') {
                        sawCr = true;
                    } else {
                        if (b == '\n' || line.length() >= MAX_SIZE_LINE) {
                            throw new IcapProtocolException(400, "malformed chunk size line");
                        }
                        line.append((char) (b & 0xff));
                    }
                }
                case DATA -> {
                    int n = Math.min(remaining, end - i);
                    sink.data(buf, i, n);
                    i += n;
                    remaining -= n;
                    if (remaining == 0) {
                        state = State.DATA_CR;
                    }
                }
                case DATA_CR -> {
                    if (buf[i++] != '\r') {
                        throw new IcapProtocolException(400, "chunk data not followed by CRLF");
                    }
                    state = State.DATA_LF;
                }
                case DATA_LF -> {
                    if (buf[i++] != '\n') {
                        throw new IcapProtocolException(400, "chunk data not followed by CRLF");
                    }
                    state = State.SIZE;
                }
                case TRAILER -> {
                    byte b = buf[i++];
                    if (++trailerBytes > MAX_TRAILER) {
                        throw new IcapProtocolException(400, "chunk trailer too large");
                    }
                    if (sawCr) {
                        if (b != '\n') {
                            throw new IcapProtocolException(400, "trailer line not ended by CRLF");
                        }
                        sawCr = false;
                        if (trailerLineEmpty) {
                            state = State.DONE;
                        }
                        trailerLineEmpty = true;
                    } else if (b == '\r') {
                        sawCr = true;
                    } else if (b == '\n') {
                        throw new IcapProtocolException(400, "bare LF in a trailer");
                    } else {
                        trailerLineEmpty = false;
                    }
                }
                case DONE -> {
                    // unreachable: the loop stops at DONE
                }
            }
        }
        return i - off;
    }

    private void sizeLineDone() {
        String s = line.toString();
        line.setLength(0);
        int semi = s.indexOf(';');
        String hex = (semi >= 0 ? s.substring(0, semi) : s).strip();
        String ext = semi >= 0 ? s.substring(semi + 1).strip() : "";
        if (hex.isEmpty() || hex.length() > 8) {
            throw new IcapProtocolException(400, "chunk size");
        }
        long size = 0;
        for (int k = 0; k < hex.length(); k++) {
            int v = Character.digit(hex.charAt(k), 16);
            if (v < 0) {
                throw new IcapProtocolException(400, "chunk size");
            }
            size = size * 16 + v;
        }
        if (size > MAX_CHUNK) {
            throw new IcapProtocolException(400, "chunk larger than allowed");
        }
        if (size == 0) {
            lastChunk = true;
            ieof = ext.equals("ieof");
            if (!ext.isEmpty() && !ieof) {
                throw new IcapProtocolException(400, "unknown last-chunk extension");
            }
            state = State.TRAILER;
            trailerLineEmpty = true;
        } else {
            if (!ext.isEmpty()) {
                throw new IcapProtocolException(400, "chunk extension on a data chunk");
            }
            remaining = (int) size;
            state = State.DATA;
        }
    }

    public boolean done() {
        return state == State.DONE;
    }

    /** True when the body ended with {@code 0; ieof}: the preview held the whole body. */
    public boolean ieof() {
        return lastChunk && ieof;
    }
}
