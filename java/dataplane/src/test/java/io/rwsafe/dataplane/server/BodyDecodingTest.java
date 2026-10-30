package io.rwsafe.dataplane.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.dataplane.icap.HeaderBlock;
import io.rwsafe.dataplane.inspect.BodyInspector;
import io.rwsafe.dataplane.inspect.CapturedBody;
import io.rwsafe.dataplane.inspect.InspectionResult;
import io.rwsafe.dataplane.inspect.JsonLeafScanner;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import io.rwsafe.platform.verdict.Verdict;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;

/**
 * Content-Encoding decompression (BY-PROTO-7) and base64 layer decoding (OFF2-3, BY-ENC-1, BY-ENC-2, BY-ENC-8) in
 * {@link BodyInspector}. Every sensitive value is built at runtime (AGENTS.md 4.5).
 */
class BodyDecodingTest {

    private static final BodyInspector INSPECTOR = new BodyInspector(DetectorSet.standard());
    private static final String JSON = "Content-Type: application/json\n";

    static InspectionResult inspect(String headers, byte[] body) {
        byte[] head = ("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n" + headers.replace("\n", "\r\n")
            + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
        HeaderBlock http = HeaderBlock.parse(head, 0, head.length, 8192, 64, 400);
        CapturedBody captured = new CapturedBody(4 * 1024 * 1024);
        captured.append(body, 0, body.length);
        return INSPECTOR.inspect(captured, http);
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    static String b64(String s) {
        return b64(utf8(s));
    }

    static byte[] gzip(byte[] plain) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(plain);
        }
        return out.toByteArray();
    }

    static byte[] zlib(byte[] plain) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DeflaterOutputStream z = new DeflaterOutputStream(out)) {
            z.write(plain);
        }
        return out.toByteArray();
    }

    static byte[] rawDeflate(byte[] plain) {
        Deflater d = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        d.setInput(plain);
        d.finish();
        byte[] buf = new byte[plain.length + 64];
        int n = d.deflate(buf);
        d.end();
        return java.util.Arrays.copyOf(buf, n);
    }

    static byte[] random(int n, long seed) {
        byte[] b = new byte[n];
        new Random(seed).nextBytes(b);
        return b;
    }

    static String prompt(String content) {
        return "{\"model\":\"synthetic\",\"messages\":[{\"role\":\"user\",\"content\":\"" + content + "\"}]}";
    }

    static boolean has(InspectionResult r, DataClass c) {
        for (Finding f : r.findings()) {
            if (f.dataClass() == c) {
                return true;
            }
        }
        return false;
    }

    static void assertRedactedJson(InspectionResult r, String secret) throws JsonLeafScanner.Malformed {
        assertNull(r.nonVerdict(), r.reason());
        assertNotNull(r.redactedBody());
        byte[] out = r.redactedBody();
        JsonLeafScanner.scan(out, out.length);
        String text = new String(out, StandardCharsets.UTF_8);
        assertFalse(text.contains(secret));
        assertTrue(text.contains("[REDACTED:TCKN]"), text);
    }

    // ---- Content-Encoding ----

    @Test
    void gzipAndDeflateBodiesAreDecodedRedactedAndStayValidJson() throws Exception {
        String tckn = Synthetic.tckn(101);
        byte[] plain = utf8(prompt("synthetic customer " + tckn + " asks about fees"));
        assertRedactedJson(inspect(JSON + "Content-Encoding: gzip\n", gzip(plain)), tckn);
        assertRedactedJson(inspect(JSON + "Content-Encoding: x-gzip\n", gzip(plain)), tckn);
        assertRedactedJson(inspect(JSON + "Content-Encoding: deflate\n", zlib(plain)), tckn);
        assertRedactedJson(inspect(JSON + "Content-Encoding: Deflate\n", rawDeflate(plain)), tckn);
    }

    @Test
    void cleanGzipBodyIsInspectedWithoutRewrite() throws Exception {
        InspectionResult r = inspect(JSON + "Content-Encoding: gzip\n", gzip(utf8(prompt("synthetic release notes"))));
        assertNull(r.nonVerdict());
        assertTrue(r.findings().isEmpty());
        assertNull(r.redactedBody());
    }

    @Test
    void ratioBombIsUninspectable() throws Exception {
        byte[] bomb = gzip(new byte[1024 * 1024]);
        InspectionResult r = inspect("Content-Type: text/plain\nContent-Encoding: gzip\n", bomb);
        assertEquals(Verdict.UNINSPECTABLE, r.nonVerdict());
        assertEquals("ENCODED", r.reason());
    }

    @Test
    void nestedOtherStackedTruncatedAndTrailingEncodingsStayEncoded() throws Exception {
        byte[] plain = utf8(prompt("synthetic"));
        byte[] once = gzip(plain);
        byte[] truncated = java.util.Arrays.copyOf(once, once.length - 3);
        byte[] trailing = java.util.Arrays.copyOf(once, once.length + 4);
        byte[][] bodies = {gzip(once), plain, gzip(plain), truncated, trailing, plain};
        String[] codings = {"gzip", "br", "gzip, gzip", "gzip", "gzip", "deflate"};
        for (int i = 0; i < bodies.length; i++) {
            InspectionResult r = inspect(JSON + "Content-Encoding: " + codings[i] + "\n", bodies[i]);
            assertEquals(Verdict.UNINSPECTABLE, r.nonVerdict(), codings[i] + " #" + i);
            assertEquals("ENCODED", r.reason(), codings[i] + " #" + i);
        }
    }

    @Test
    void undeclaredGzipStaysBinary() throws Exception {
        InspectionResult r = inspect("Content-Type: text/plain\n", gzip(utf8("synthetic " + Synthetic.tckn(3))));
        assertEquals(Verdict.UNINSPECTABLE, r.nonVerdict());
        assertEquals("BINARY", r.reason());
    }

    // ---- base64 layers ----

    @Test
    void base64CloudKeyInAJsonLeafIsASecret() {
        InspectionResult r = inspect(JSON, utf8(prompt("deploy with " + b64(Synthetic.awsKey()))));
        assertNull(r.nonVerdict(), r.reason());
        assertTrue(has(r, DataClass.SECRET));
    }

    @Test
    void base64TcknReplacesTheWholeField() {
        String tckn = Synthetic.tckn(7);
        String encoded = b64("synthetic customer " + tckn);
        InspectionResult r = inspect(JSON, utf8(prompt("please summarise " + encoded + " for me")));
        assertTrue(has(r, DataClass.TCKN));
        String out = new String(r.redactedBody(), StandardCharsets.UTF_8);
        assertFalse(out.contains(encoded));
        assertFalse(out.contains("please summarise"), "the whole field is replaced, never a partial rewrite");
        assertTrue(out.contains("\"content\":\"[REDACTED:TCKN]\""), out);
    }

    @Test
    void bareBase64TcknIsFound() {
        String tckn = Synthetic.tckn(8);
        assertTrue(has(inspect(JSON, utf8(prompt(b64(tckn)))), DataClass.TCKN));
        assertTrue(has(inspect(JSON, utf8(prompt(b64(tckn).replace("=", "")))), DataClass.TCKN));
    }

    @Test
    void doubleBase64IsFound() {
        String tckn = Synthetic.tckn(9);
        assertTrue(has(inspect(JSON, utf8(prompt(b64(b64("synthetic customer " + tckn))))), DataClass.TCKN));
        assertTrue(has(inspect(JSON, utf8(prompt(b64(b64(tckn))))), DataClass.TCKN));
        assertTrue(has(inspect(JSON, utf8(prompt(b64(b64(Synthetic.awsKey()))))), DataClass.SECRET));
    }

    @Test
    void urlSafeAndMimeWrappedBase64AreDecoded() {
        String key = Synthetic.awsKey();
        String urlSafe = Base64.getUrlEncoder().withoutPadding().encodeToString(utf8("synthetic ?>?> " + key));
        assertTrue(has(inspect(JSON, utf8(prompt(urlSafe))), DataClass.SECRET));
        String mime = Base64.getMimeEncoder().encodeToString(utf8("synthetic ".repeat(12) + key));
        assertTrue(has(inspect("Content-Type: text/plain\n", utf8(mime)), DataClass.SECRET));
    }

    @Test
    void base64InATextBodyIsFoundAndNotRewritable() {
        InspectionResult r = inspect("Content-Type: text/plain\n", utf8("synthetic " + b64(Synthetic.awsKey())));
        assertNull(r.nonVerdict());
        assertTrue(has(r, DataClass.SECRET));
        assertFalse(r.redactable());
    }

    @Test
    void randomBlobAbove256BytesIsUndecodable() {
        InspectionResult encoded = inspect(JSON, utf8(prompt(b64(random(300, 1)))));
        assertEquals(Verdict.UNINSPECTABLE, encoded.nonVerdict());
        assertEquals("UNDECODABLE_BLOB", encoded.reason());
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        Random rnd = new Random(2);
        StringBuilder raw = new StringBuilder();
        for (int i = 0; i < 301; i++) {
            raw.append(alphabet.charAt(rnd.nextInt(64)));
        }
        InspectionResult undecodable = inspect(JSON, utf8(prompt(raw.toString())));
        assertEquals("UNDECODABLE_BLOB", undecodable.reason());
        String wrapped = Base64.getMimeEncoder().encodeToString(random(600, 3));
        assertEquals("UNDECODABLE_BLOB", inspect("Content-Type: text/plain\n", utf8(wrapped)).reason());
    }

    @Test
    void thirdLayerIsAResidualBlob() {
        String text = "synthetic release notes for the quarterly review, nothing sensitive at all. ".repeat(4);
        InspectionResult r = inspect(JSON, utf8(prompt(b64(b64(b64(text))))));
        assertEquals(Verdict.UNINSPECTABLE, r.nonVerdict());
        assertEquals("UNDECODABLE_BLOB", r.reason());
        assertNull(inspect(JSON, utf8(prompt(b64(b64(text))))).nonVerdict());
    }

    @Test
    void embeddedFilesAreUninspectable() {
        byte[] pdf = utf8("%PDF-1.4\nsynthetic\n%%EOF\n");
        assertEquals("EMBEDDED_FILE", inspect(JSON, utf8(prompt(b64(pdf)))).reason());
        byte[] zip = {'P', 'K', 3, 4, 20, 0, 0, 0, 8, 0, 1, 2, 3, 4, 5, 6};
        assertEquals("EMBEDDED_FILE", inspect(JSON, utf8(prompt(b64(zip)))).reason());
        assertEquals("EMBEDDED_FILE", inspect(JSON, utf8(prompt(b64(png(400))))).reason());
    }

    @Test
    void ordinaryTrafficDoesNotTrip() {
        String[] values = {
            b64(png(120)),
            "msg_01SyntheticIdentifierAbCdEf",
            "0123456789abcdef".repeat(4),
            "0123456789abcdef".repeat(20),
            "https://docs.example.com/guides/synthetic/release-notes/2026/quarterly/overview?page=2",
            "a".repeat(400),
            "-".repeat(400),
            "internationalization_and_localization_synthetic_identifier_name",
            b64("synthetic release notes, nothing sensitive. ".repeat(30)),
            "synthetic plain prose with words and numbers 12345 and nothing encoded in it at all",
        };
        for (String v : values) {
            InspectionResult r = inspect(JSON, utf8(prompt(v)));
            assertNull(r.nonVerdict(), r.reason() + " for " + v.substring(0, Math.min(24, v.length())));
            assertTrue(r.findings().isEmpty(), v.substring(0, Math.min(24, v.length())));
        }
    }

    /** A PNG-signature byte array of {@code n} bytes (a synthetic image header, no real image). */
    static byte[] png(int n) {
        byte[] b = random(n, n);
        byte[] sig = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
        System.arraycopy(sig, 0, b, 0, sig.length);
        return b;
    }
}
