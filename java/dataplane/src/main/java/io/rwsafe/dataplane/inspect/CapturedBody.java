package io.rwsafe.dataplane.inspect;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;
import java.util.Arrays;

/**
 * The decoded body of one transaction, held in memory up to a cap (ICAP spec §3: 4 MiB for REQMOD). Bytes beyond the cap
 * are counted and discarded, never stored; {@link #oversize()} then makes the transaction {@code UNINSPECTABLE}.
 */
@BodyBearing
public final class CapturedBody {

    private final int cap;
    private byte[] buf;
    private int len;
    private long total;

    public CapturedBody(int cap) {
        this.cap = cap;
        this.buf = new byte[Math.min(cap, 16 * 1024)];
    }

    public void append(byte[] data, int off, int n) {
        total += n;
        if (len >= cap) {
            return;
        }
        int keep = (int) Math.min(n, (long) cap - len);
        if (len + keep > buf.length) {
            buf = Arrays.copyOf(buf, (int) Math.min(cap, Math.max((long) buf.length * 2, (long) len + keep)));
        }
        System.arraycopy(data, off, buf, len, keep);
        len += keep;
    }

    public boolean oversize() {
        return total > cap;
    }

    /** The most bytes this body keeps; also the bound for a decoded body. */
    public int cap() {
        return cap;
    }

    public int length() {
        return len;
    }

    public long totalBytes() {
        return total;
    }

    /** The captured bytes {@code [0, length())}; the array may be longer. */
    @BodyContent
    public byte[] bytes() {
        return buf;
    }

    @Override
    public String toString() {
        return "CapturedBody[length=" + len + ", total=" + total + "]";
    }
}
