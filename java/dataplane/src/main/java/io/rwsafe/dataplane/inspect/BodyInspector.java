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
 * Inspects a captured body (ICAP spec §4.3). JSON: every string and number leaf is normalised and scanned and can be
 * rewritten. Form-encoded bodies are percent-decoded and text bodies decoded as strict UTF-8, then scanned; they are not
 * rewritable. Everything the engine cannot read yet is a non-verdict, never an allow (PR 11 review D-01, D-02):
 * declared encodings, compressed or binary payloads (by magic bytes or invalid UTF-8), multipart and any other media
 * type, bodies above the cap, scans that reach the finding limit and normalisation that expands beyond a bound.
 *
 * <p>Not yet in this slice: decompression (BY-PROTO-7), base64 layer decoding (OFF2-3) and the file pipeline (BY-FILE-*).
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
        if (encoded(http.first("Content-Encoding"))) {
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "ENCODED");
        }
        if (body.length() == 0) {
            return InspectionResult.inspected(List.of(), true, null);
        }
        // N-03: the detectors read UTF-8; another declared charset (UTF-16 interleaves NUL bytes) is not readable yet.
        if (!UTF8_CHARSETS.contains(http.charset())) {
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "UNSUPPORTED_CHARSET");
        }
        String mediaType = http.mediaType();
        byte[] bytes = body.bytes();
        int len = body.length();
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
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "FINDING_LIMIT");
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
        for (JsonLeaf leaf : leaves) {
            String normalised = Normaliser.normalise(leaf.text());
            normalisedChars += normalised.length();
            if (normalisedChars > (long) MAX_EXPANSION * len + 64) {
                return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "NORMALISATION");
            }
            List<Finding> found = detectors.scan(normalised);
            if (found.isEmpty()) {
                continue;
            }
            all.addAll(found);
            if (DetectorSet.overLimit(all)) {
                return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "FINDING_LIMIT");
            }
            if (rewritten == null) {
                rewritten = new ByteArrayOutputStream(len);
            }
            rewritten.write(bytes, cursor, leaf.rawStart() - cursor);
            rewritten.writeBytes(JsonLeafScanner.encode(Redactor.redact(normalised, found)));
            cursor = leaf.rawEnd();
        }
        if (rewritten == null) {
            return InspectionResult.inspected(all, true, null);
        }
        rewritten.write(bytes, cursor, len - cursor);
        return InspectionResult.inspected(all, true, rewritten.toByteArray());
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
        int b0 = b[0] & 0xff;
        int b1 = b[1] & 0xff;
        if ((b0 == 0x1f && b1 == 0x8b) || (b0 == 0x78 && (b1 == 0x01 || b1 == 0x5e || b1 == 0x9c || b1 == 0xda))) {
            return true;
        }
        return startsWith(b, len, 'P', 'K', 3, 4) || startsWith(b, len, '%', 'P', 'D', 'F')
            || startsWith(b, len, '7', 'z', 0xbc, 0xaf) || startsWith(b, len, 0xfd, '7', 'z', 'X')
            || startsWith(b, len, 0x28, 0xb5, 0x2f, 0xfd) || startsWith(b, len, 'B', 'Z', 'h');
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
