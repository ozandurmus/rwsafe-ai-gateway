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

    // ---- PR 17 second review ----

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** D-01: an embedded file or blob never discards findings, before or after it; the rewrite still applies. */
    @Test
    void findingsSurviveAnEmbeddedFileOrABlob() {
        String key = Synthetic.awsKey();
        String tckn = Synthetic.tckn(31);
        String pdf = b64(utf8("%PDF-1.4\nsynthetic\n"));
        InspectionResult r = inspect(JSON, utf8("{\"a\":\"synthetic " + key + "\",\"b\":\"" + pdf
            + "\",\"c\":\"customer " + tckn + "\"}"));
        assertEquals(Verdict.UNINSPECTABLE, r.nonVerdict());
        assertEquals("EMBEDDED_FILE", r.reason());
        assertTrue(has(r, DataClass.SECRET));
        assertTrue(has(r, DataClass.TCKN), "a field after the file is still inspected");
        String out = new String(r.redactedBody(), StandardCharsets.UTF_8);
        assertFalse(out.contains(tckn));
        assertTrue(out.contains("[REDACTED:TCKN]"));
        InspectionResult text = inspect("Content-Type: text/plain\n",
            utf8("synthetic " + key + " " + b64(random(300, 5))));
        assertEquals("UNDECODABLE_BLOB", text.reason());
        assertTrue(has(text, DataClass.SECRET));
        InspectionResult sameField = inspect(JSON, utf8(prompt(b64("customer " + tckn) + " " + b64(random(300, 6)))));
        assertEquals("UNDECODABLE_BLOB", sameField.reason());
        assertTrue(has(sameField, DataClass.TCKN), "a decoded-layer finding before the blob is kept");
    }

    /** D-02 (1): a NUL, an invalid byte or UTF-16LE does not hide a value inside a decoded layer. */
    @Test
    void nulInvalidAndUtf16LayersAreStillScanned() {
        String key = Synthetic.awsKey();
        String tckn = Synthetic.tckn(32);
        byte[][] layers = {
            concat(new byte[] {0}, utf8("synthetic " + key)),
            concat(new byte[] {(byte) 0xff}, utf8("synthetic " + key)),
            ("synthetic " + key).getBytes(StandardCharsets.UTF_16LE),
            concat(new byte[] {(byte) 0xff, 0}, utf8("customer " + tckn)),
        };
        DataClass[] expected = {DataClass.SECRET, DataClass.SECRET, DataClass.SECRET, DataClass.TCKN};
        for (int i = 0; i < layers.length; i++) {
            InspectionResult r = inspect(JSON, utf8(prompt(b64(layers[i]))));
            assertTrue(has(r, expected[i]), "case " + i);
        }
    }

    /** D-02 (2): a third layer that decodes to text is a residual blob at any length. */
    @Test
    void aReadableThirdLayerIsABlobAtAnyLength() {
        String[] values = {b64(b64(b64(Synthetic.awsKey()))), b64(b64(b64(Synthetic.tckn(33))))};
        for (String v : values) {
            assertTrue(v.length() <= 256);
            InspectionResult r = inspect(JSON, utf8(prompt(v)));
            assertEquals(Verdict.UNINSPECTABLE, r.nonVerdict());
            assertEquals("UNDECODABLE_BLOB", r.reason());
        }
    }

    /** D-02 (3): low-entropy padding around random bytes does not dilute the entropy below the limit. */
    @Test
    void paddingDoesNotDiluteEntropy() {
        byte[] nulPadded = concat(new byte[600], random(200, 34));
        byte[] letterPadded = concat(utf8("a".repeat(500)), random(200, 35));
        for (byte[] layer : new byte[][] {nulPadded, letterPadded}) {
            assertEquals("UNDECODABLE_BLOB", inspect(JSON, utf8(prompt(b64(layer)))).reason());
        }
    }

    /** D-03: a base64 run glued to a prefix or a URL path is realigned and decoded. */
    @Test
    void prefixedAndPathGluedBase64IsRealigned() {
        String enc = b64("synthetic " + Synthetic.awsKey());
        for (String prefix : new String[] {"-", "/", "_+", "v1/items/", "x", "xy", "abc"}) {
            assertTrue(has(inspect(JSON, utf8(prompt(prefix + enc))), DataClass.SECRET), prefix);
        }
    }

    /** D-04: "x^" and "BZh" are text; bzip2 needs its full header. */
    @Test
    void textThatStartsLikeAMagicIsText() throws Exception {
        String[] texts = {"x^2 + y^2 = 1 is a synthetic circle", "BZh synthetic notes"};
        for (String t : texts) {
            assertNull(inspect("Content-Type: text/plain\n", utf8(t)).nonVerdict(), t);
            assertNull(inspect(JSON, utf8(prompt(b64(t + " for the synthetic review")))).nonVerdict(), t);
            assertNull(inspect("Content-Type: text/plain\nContent-Encoding: gzip\n", gzip(utf8(t))).nonVerdict(), t);
        }
        byte[] bzip2 = concat(new byte[] {'B', 'Z', 'h', '9', 0x31, 0x41, 0x59, 0x26, 0x53, 0x59}, random(20, 36));
        assertEquals("BINARY", inspect("Content-Type: text/plain\n", bzip2).reason());
        assertEquals("EMBEDDED_FILE", inspect(JSON, utf8(prompt(b64(bzip2)))).reason());
    }

    /** Q-2: a WebP image above 256 characters is an embedded file; a small one is not. */
    @Test
    void webpAbove256CharactersIsAnEmbeddedFile() {
        byte[] large = random(400, 37);
        byte[] small = random(60, 38);
        for (byte[] b : new byte[][] {large, small}) {
            System.arraycopy(utf8("RIFF"), 0, b, 0, 4);
            System.arraycopy(utf8("WEBP"), 0, b, 8, 4);
        }
        assertEquals("EMBEDDED_FILE", inspect(JSON, utf8(prompt(b64(large)))).reason());
        assertNull(inspect(JSON, utf8(prompt(b64(small)))).nonVerdict());
    }

    /** A PNG-signature byte array of {@code n} bytes (a synthetic image header, no real image). */
    static byte[] png(int n) {
        byte[] b = random(n, n);
        byte[] sig = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
        System.arraycopy(sig, 0, b, 0, sig.length);
        return b;
    }
}
