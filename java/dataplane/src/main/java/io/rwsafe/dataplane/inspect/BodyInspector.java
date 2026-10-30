package io.rwsafe.dataplane.inspect;

import io.rwsafe.dataplane.icap.HeaderBlock;
import io.rwsafe.dataplane.icap.Ows;
import io.rwsafe.dataplane.icap.Tokens;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.Normaliser;
import io.rwsafe.detect.Redactor;
import io.rwsafe.platform.verdict.Finding;
import io.rwsafe.platform.verdict.Verdict;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Inspects a captured body (ICAP spec §4.3). A declared single gzip or deflate {@code Content-Encoding} is decoded first
 * within 8x the input and the body cap ({@link ContentDecoding}); a rewrite of a decoded body is identity-encoded. JSON:
 * every string and number leaf is normalised and scanned and can be rewritten. Form-encoded bodies are percent-decoded
 * and text bodies decoded as strict UTF-8, then scanned; they are not rewritable. Every string leaf and every text body
 * also has its base64 layers decoded and scanned ({@link Base64Layers}); a finding inside a decoded layer replaces the
 * whole field with the class token. Everything the engine cannot read is a non-verdict, never an allow (PR 11 review
 * D-01, D-02): other or stacked encodings, compressed or binary payloads (by magic bytes or invalid UTF-8), multipart and
 * any other media type, bodies above the cap, embedded files and undecodable blobs, scans that reach the finding limit
 * and normalisation that expands beyond a bound.
 *
 * <p>Not yet in this slice: the file pipeline (BY-FILE-*), hex and other non-base64 layers, gzip inside base64 (BY-ENC-9:
 * {@code EMBEDDED_FILE} for now).
 */
public final class BodyInspector {

    /** NFKC can expand a character up to 18 times; more than this factor over the input is refused (D-12). */
    private static final int MAX_EXPANSION = 4;

    private static final Set<String> UTF8_CHARSETS = Set.of("", "utf-8", "utf8", "us-ascii");

    private static final Set<String> TEXT_LIKE = Set.of("application/xml", "application/javascript",
        "application/graphql", "application/x-ndjson", "application/ndjson", "application/yaml", "application/x-yaml");

    private final DetectorSet detectors;

    public BodyInspector(DetectorSet detectors) {
        this.detectors = detectors;
    }

    public InspectionResult inspect(CapturedBody body, HeaderBlock http) {
        if (body.oversize()) {
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "OVERSIZE");
        }
        byte[] bytes = body.bytes();
        int len = body.length();
        String contentEncoding = http.first("Content-Encoding");
        if (encoded(contentEncoding)) {
            byte[] decoded = ContentDecoding.decode(contentEncoding, bytes, len,
                (int) Math.min((long) ContentDecoding.MAX_RATIO * len, body.cap()));
            if (decoded == null || ContentDecoding.compressed(decoded, decoded.length)) {
                return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "ENCODED");
            }
            bytes = decoded;
            len = decoded.length;
        }
        if (len == 0) {
            return InspectionResult.inspected(List.of(), true, null);
        }
        // N-03: the detectors read UTF-8; another declared charset (UTF-16 interleaves NUL bytes) is not readable yet.
        if (!UTF8_CHARSETS.contains(http.charset())) {
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "UNSUPPORTED_CHARSET");
        }
        String mediaType = http.mediaType();
        if (binaryMagic(bytes, len)) {
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "BINARY");
        }
        if (mediaType.equals("application/json") || mediaType.endsWith("+json")) {
            return inspectJson(bytes, len);
        }
        if (mediaType.equals("application/x-www-form-urlencoded")) {
            byte[] decoded = percentDecode(bytes, len);
            String text = strictUtf8(decoded, decoded.length);
            return text == null ? InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "BINARY") : inspectText(text);
        }
        if (mediaType.startsWith("multipart/")) {
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "MULTIPART");
        }
        if (mediaType.isEmpty() || mediaType.startsWith("text/") || mediaType.endsWith("+xml")
            || TEXT_LIKE.contains(mediaType)) {
            String text = strictUtf8(bytes, len);
            return text == null ? InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "BINARY") : inspectText(text);
        }
        return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "UNSUPPORTED_MEDIA");
    }

    /** Scans one decoded text (a RESPMOD window or any non-JSON body). */
    public List<Finding> scanText(String text) {
        return detectors.scan(Normaliser.normalise(text));
    }

    /** Scans text that is already normalised. */
    public List<Finding> scanNormalised(String normalised) {
        return detectors.scan(normalised);
    }

    private InspectionResult inspectText(String text) {
        String normalised = Normaliser.normalise(text);
        if (normalised.length() > MAX_EXPANSION * text.length() + 64) {
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "NORMALISATION");
        }
        List<Finding> found = detectors.scan(normalised);
        if (DetectorSet.overLimit(found)) {
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "FINDING_LIMIT", found, false, null);
        }
        Base64Layers.Outcome layers = Base64Layers.inspect(normalised, detectors);
        if (!layers.findings().isEmpty()) {
            found = new ArrayList<>(found);
            found.addAll(layers.findings());
            if (DetectorSet.overLimit(found)) {
                return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "FINDING_LIMIT", found, false, null);
            }
        }
        if (layers.reason() != null) {
            // D-01: the findings travel with the non-verdict; a finding that blocks still blocks.
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, layers.reason(), found, false, null);
        }
        return InspectionResult.inspected(found, false, null);
    }

    private InspectionResult inspectJson(byte[] bytes, int len) {
        List<JsonLeaf> leaves;
        try {
            leaves = JsonLeafScanner.scan(bytes, len);
        } catch (JsonLeafScanner.Malformed e) {
            return InspectionResult.nonVerdict(Verdict.MALFORMED, "JSON");
        }
        List<Finding> all = new ArrayList<>();
        ByteArrayOutputStream rewritten = null;
        int cursor = 0;
        long normalisedChars = 0;
        String blobReason = null;
        for (JsonLeaf leaf : leaves) {
            String normalised = Normaliser.normalise(leaf.text());
            normalisedChars += normalised.length();
            if (normalisedChars > (long) MAX_EXPANSION * len + 64) {
                return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "NORMALISATION", all, false, null);
            }
            List<Finding> found = detectors.scan(normalised);
            Base64Layers.Outcome layers = leaf.number() ? Base64Layers.Outcome.NONE
                : Base64Layers.inspect(normalised, detectors);
            all.addAll(found);
            all.addAll(layers.findings());
            if (layers.stops() || DetectorSet.overLimit(all)) {
                String reason = layers.stops() ? layers.reason() : "FINDING_LIMIT";
                return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, reason, all, false, null);
            }
            // D-01: an embedded file or blob is remembered and the rest of the body is still inspected and redacted;
            // recheck D-06: the most severe reason of all fields is kept.
            blobReason = Base64Layers.worse(blobReason, layers.reason());
            if (found.isEmpty() && layers.findings().isEmpty()) {
                continue;
            }
            if (rewritten == null) {
                rewritten = new ByteArrayOutputStream(len);
            }
            rewritten.write(bytes, cursor, leaf.rawStart() - cursor);
            // OFF2-3: a finding inside a decoded layer replaces the whole field, never a partial rewrite of encoded text.
            String replacement = layers.findings().isEmpty() ? Redactor.redact(normalised, found)
                : layers.findings().get(0).dataClass().redactionToken();
            rewritten.writeBytes(JsonLeafScanner.encode(replacement));
            cursor = leaf.rawEnd();
        }
        byte[] redacted = null;
        if (rewritten != null) {
            rewritten.write(bytes, cursor, len - cursor);
            redacted = rewritten.toByteArray();
        }
        return blobReason == null ? InspectionResult.inspected(all, true, redacted)
            : InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, blobReason, all, true, redacted);
    }

    /** Any token of any Content-Encoding value other than {@code identity} (D-03). */
    public static boolean encoded(String contentEncoding) {
        if (contentEncoding == null) {
            return false;
        }
        for (String token : Tokens.split(contentEncoding, ',')) {
            String t = Ows.trim(token).toLowerCase(Locale.ROOT);
            if (!t.isEmpty() && !t.equals("identity")) {
                return true;
            }
        }
        return false;
    }

    /** gzip, zlib, zip, PDF, 7z, xz, zstd and bzip2 signatures. */
    static boolean binaryMagic(byte[] b, int len) {
        if (len < 2) {
            return false;
        }
        if (ContentDecoding.compressed(b, len)) {
            return true;
        }
        return startsWith(b, len, 'P', 'K', 3, 4) || startsWith(b, len, '%', 'P', 'D', 'F')
            || startsWith(b, len, '7', 'z', 0xbc, 0xaf) || startsWith(b, len, 0xfd, '7', 'z', 'X')
            || startsWith(b, len, 0x28, 0xb5, 0x2f, 0xfd) || bzip2(b, len);
    }

    /** PR 17 review D-04: "BZh" alone is text; bzip2 is BZh, a level 1-9, then the block or end-of-stream magic. */
    private static boolean bzip2(byte[] b, int len) {
        if (len < 10 || !startsWith(b, len, 'B', 'Z', 'h') || b[3] < '1' || b[3] > '9') {
            return false;
        }
        boolean block = (b[4] & 0xff) == 0x31 && (b[5] & 0xff) == 0x41 && (b[6] & 0xff) == 0x59
            && (b[7] & 0xff) == 0x26 && (b[8] & 0xff) == 0x53 && (b[9] & 0xff) == 0x59;
        boolean end = (b[4] & 0xff) == 0x17 && (b[5] & 0xff) == 0x72 && (b[6] & 0xff) == 0x45
            && (b[7] & 0xff) == 0x38 && (b[8] & 0xff) == 0x50 && (b[9] & 0xff) == 0x90;
        return block || end;
    }

    private static boolean startsWith(byte[] b, int len, int... sig) {
        if (len < sig.length) {
            return false;
        }
        for (int i = 0; i < sig.length; i++) {
            if ((b[i] & 0xff) != sig[i]) {
                return false;
            }
        }
        return true;
    }

    /** Strict UTF-8 without NUL (N-03: NUL-interleaved text would split every value); null when not readable. */
    public static String strictUtf8(byte[] b, int len) {
        for (int i = 0; i < len; i++) {
            if (b[i] == 0) {
                return null;
            }
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(b, 0, len)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    /** {@code application/x-www-form-urlencoded}: '+' is a space, %XX is a byte; the result is decoded as UTF-8. */
    static byte[] percentDecode(byte[] b, int len) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(len);
        for (int i = 0; i < len; i++) {
            byte c = b[i];
            if (c == '+') {
                out.write(' ');
            } else if (c == '%' && i + 2 < len && Character.digit(b[i + 1], 16) >= 0 && Character.digit(b[i + 2], 16) >= 0) {
                out.write(Character.digit(b[i + 1], 16) * 16 + Character.digit(b[i + 2], 16));
                i += 2;
            } else {
                out.write(c);
            }
        }
        return out.toByteArray();
    }
}
