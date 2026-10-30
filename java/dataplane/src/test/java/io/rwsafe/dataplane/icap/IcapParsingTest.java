package io.rwsafe.dataplane.icap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class IcapParsingTest {

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static IcapRequest parse(String s) {
        byte[] b = ascii(s);
        return IcapRequest.parse(b, 0, b.length);
    }

    @Test
    void parsesAReqmodHead() {
        IcapRequest r = parse("REQMOD icap://icap.example.invalid:1344/reqmod-ai?x=1 ICAP/1.0\r\n"
            + "Host: icap.example.invalid\r\nEncapsulated: req-hdr=0, req-body=120\r\nPreview: 0\r\nAllow: 204\r\n\r\n");
        assertEquals(IcapRequest.Method.REQMOD, r.method());
        assertEquals("/reqmod-ai", r.servicePath());
        assertEquals(120, r.bodySection().offset());
        assertEquals(0, r.preview());
        assertTrue(r.allows204());
        assertArrayEquals(new int[] {0, 120}, r.headerRange("req-hdr"));
    }

    @Test
    void refusesBadFrames() {
        assertEquals(400, assertThrows(IcapProtocolException.class, () -> parse(
            "REQMOD icap://h/reqmod-ai ICAP/1.0\r\nEncapsulated: req-body=0, req-hdr=10\r\n\r\n")).status());
        assertEquals(400, assertThrows(IcapProtocolException.class, () -> parse(
            "REQMOD icap://h/reqmod-ai ICAP/1.0\r\nEncapsulated: res-hdr=0, res-body=10\r\n\r\n")).status());
        assertEquals(400, assertThrows(IcapProtocolException.class, () -> parse(
            "REQMOD icap://h/reqmod-ai ICAP/1.0\r\nEncapsulated: req-hdr=0, req-body=10\r\n\tfolded\r\n\r\n")).status());
        assertEquals(400, assertThrows(IcapProtocolException.class, () -> parse(
            "REQMOD icap://h/reqmod-ai ICAP/1.0\nEncapsulated: req-hdr=0, req-body=10\r\n\r\n")).status());
        assertEquals(405, assertThrows(IcapProtocolException.class, () -> parse(
            "PATCH icap://h/reqmod-ai ICAP/1.0\r\nEncapsulated: null-body=0\r\n\r\n")).status());
        assertEquals(400, assertThrows(IcapProtocolException.class, () -> parse(
            "REQMOD icap://h/reqmod-ai ICAP/1.0\r\nEncapsulated: req-hdr=0, req-body=10\r\nPreview: 999999\r\n\r\n"))
            .status());
    }

    @Test
    void chunkedDecodingAcrossArbitrarySplits() {
        byte[] wire = ascii("5\r\nhello\r\n6\r\n world\r\n0; ieof\r\n\r\nNEXT");
        for (int split = 1; split < wire.length; split++) {
            ChunkedDecoder d = new ChunkedDecoder();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int used = d.feed(wire, 0, split, out::write);
            if (!d.done()) {
                used += d.feed(wire, used, wire.length - used, out::write);
            }
            assertTrue(d.done());
            assertTrue(d.ieof());
            assertEquals("hello world", out.toString(StandardCharsets.US_ASCII));
            assertEquals(wire.length - 4, used, "bytes after the body belong to the next message");
        }
    }

    @Test
    void chunkedDecoderRefusesGarbage() {
        assertThrows(IcapProtocolException.class, () -> new ChunkedDecoder().feed(ascii("zz\r\n"), 0, 4, (b, o, n) -> { }));
        assertThrows(IcapProtocolException.class,
            () -> new ChunkedDecoder().feed(ascii("3\r\nabcX"), 0, 7, (b, o, n) -> { }));
        assertThrows(IcapProtocolException.class,
            () -> new ChunkedDecoder().feed(ascii("ffffffff\r\n"), 0, 10, (b, o, n) -> { }));
    }

    @Test
    void rewriteRefusesControlCharactersInValues() {
        byte[] head = ascii("POST / HTTP/1.1\r\nHost: a.example.invalid\r\n\r\n");
        HeaderBlock h = HeaderBlock.parse(head, 0, head.length, 8192, 64, 400);
        assertThrows(IllegalArgumentException.class,
            () -> h.rewrite(java.util.List.of(), java.util.List.of(new HeaderBlock.Field("X", "a\r\nInjected: 1"))));
    }
}
