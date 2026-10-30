package io.rwsafe.dataplane.events;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * The C3 content of one verdict event (ADR-009, PO decision Q-4 b): the body the engine already rewrote with class tokens,
 * never the original bytes. The request thread only wraps the array the redaction produced (no copy, no decoding); the
 * shipper thread decodes it up to {@link #cap()} bytes when it serialises the event. The array is never modified after
 * the redaction made it.
 */
@BodyBearing
public final class CapturedText {

    private final byte[] redacted;
    private final int cap;
    /** Copies of the sizes, so the printable members never read the content fields (the AGENTS.md 4.14 fence). */
    private final int bytes;
    private final int bound;

    private CapturedText(byte[] redacted, int cap) {
        this.redacted = redacted;
        this.cap = cap;
        this.bytes = redacted.length;
        this.bound = cap;
    }

    /**
     * @param redacted the rewritten body exactly as the redaction returned it
     * @param cap      the most bytes that travel; the rest is cut at a character boundary and {@link #truncated()} is set
     */
    public static CapturedText ofRedacted(byte[] redacted, int cap) {
        if (redacted == null || cap <= 0) {
            throw new IllegalArgumentException("a capture needs a rewritten body and a positive bound");
        }
        return new CapturedText(redacted, cap);
    }

    /** The rewritten body's size in bytes before the bound. */
    public int redactedBytes() {
        return bytes;
    }

    public int cap() {
        return bound;
    }

    public boolean truncated() {
        return bytes > bound;
    }

    /**
     * The redacted text up to {@link #cap()} bytes, cut at the last whole UTF-8 character; malformed input is replaced.
     * Called on the shipper thread only.
     */
    @BodyContent
    public String text() {
        int n = Math.min(redacted.length, cap);
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE);
        CharBuffer out = CharBuffer.allocate(n);
        ByteBuffer in = ByteBuffer.wrap(redacted, 0, n);
        boolean whole = redacted.length <= cap;
        // At a cut the input does not end there: an incomplete sequence at the cut stays unread and is dropped.
        CoderResult r = decoder.decode(in, out, whole);
        if (whole && !r.isOverflow()) {
            decoder.flush(out);
        }
        return out.flip().toString();
    }

    /** Never prints the content (AGENTS.md 4.14). */
    @Override
    public String toString() {
        return "CapturedText[bytes=" + bytes + ", cap=" + bound + "]";
    }
}
