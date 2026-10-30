package io.rwsafe.dataplane.inspect;

import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.Normaliser;
import io.rwsafe.detect.Redactor;
import io.rwsafe.platform.verdict.Finding;
import io.rwsafe.platform.verdict.Verdict;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Inspects a captured body (ICAP spec §4.3): every JSON string leaf is normalised and scanned; any other body is scanned
 * as UTF-8 text and is not rewritable. Oversize, compressed and malformed bodies are non-verdicts, never an allow.
 *
 * <p>Not yet in this slice: decompression of declared encodings (BY-PROTO-7), base64 layer decoding (OFF2-3) and the file
 * pipeline (BY-FILE-*); an encoded body is {@code UNINSPECTABLE(ENCODED)} until they land.
 */
public final class BodyInspector {

    private final DetectorSet detectors;

    public BodyInspector(DetectorSet detectors) {
        this.detectors = detectors;
    }

    public InspectionResult inspect(CapturedBody body, String mediaType, String contentEncoding) {
        if (body.oversize()) {
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "OVERSIZE");
        }
        if (contentEncoding != null && !contentEncoding.isBlank()
            && !contentEncoding.strip().toLowerCase(Locale.ROOT).equals("identity")) {
            return InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, "ENCODED");
        }
        if (body.length() == 0) {
            return InspectionResult.inspected(List.of(), true, null);
        }
        if (mediaType.equals("application/json") || mediaType.endsWith("+json")) {
            return inspectJson(body.bytes(), body.length());
        }
        return inspectText(new String(body.bytes(), 0, body.length(), StandardCharsets.UTF_8));
    }

    /** Scans one decoded text (a RESPMOD window or any non-JSON body). */
    public List<Finding> scanText(String text) {
        return detectors.scan(Normaliser.normalise(text));
    }

    private InspectionResult inspectText(String text) {
        return InspectionResult.inspected(scanText(text), false, null);
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
        for (JsonLeaf leaf : leaves) {
            String normalised = Normaliser.normalise(leaf.text());
            List<Finding> found = detectors.scan(normalised);
            if (found.isEmpty()) {
                continue;
            }
            all.addAll(found);
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
}
