package io.rwsafe.dataplane.inspect;

import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.Normaliser;
import io.rwsafe.platform.verdict.Finding;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Base64 layer decoding of one field (OFF2-3, ICAP spec §3, BY-ENC-1, BY-ENC-2, BY-ENC-8). A linear scanner (no regular
 * expression) finds runs of the standard or URL-safe base64 alphabet, joined across single line breaks (MIME wrapping),
 * of at least {@link #MIN_RUN} characters, and decodes them up to {@link #MAX_DEPTH} layers deep and at most
 * {@link #MAX_DECODED} bytes per field. Decoded text (strict UTF-8, UTF-8 with NUL bytes removed, or UTF-16LE) is
 * normalised, scanned and its own runs decoded in turn; decoded bytes that are not text are still scanned after NUL
 * removal and replacement decoding (PR 17 review D-02). A run that does not decode to text as a whole is retried without
 * its leading {@code - _ + /}, split at {@code /}, and at offsets 1 to 3 (D-03).
 *
 * <p>The outcome is the findings inside decoded layers (the caller replaces the whole field) and, when one applies, a
 * non-verdict reason; the findings are always kept with it (D-01):
 * <ul>
 *   <li>{@code EMBEDDED_FILE}: decoded bytes start with a document, archive or compression signature (any size), or an
 *       image signature in a run above {@link #BLOB_LIMIT} characters; the file pipeline (BY-FILE-*) is not built;</li>
 *   <li>{@code UNDECODABLE_BLOB}: a run above {@link #BLOB_LIMIT} characters that is not text and whose Shannon entropy,
 *       the highest over any {@link #BLOB_LIMIT}-character window, is over {@link #ENTROPY_LIMIT} bits per character; a
 *       third layer that decodes to text, at any length; or the per-field decode budget is spent;</li>
 *   <li>{@code NORMALISATION} and {@code FINDING_LIMIT} as for the outer text; these and a spent budget stop the scan
 *       ({@link Outcome#stops()}), the others let the caller go on inspecting the rest of the body.</li>
 * </ul>
 * A short run that decodes to binary (a small icon, an opaque token) is ignored: it carries too little to matter and is
 * what legitimate traffic is full of.
 */
final class Base64Layers {

    /** A bare base64 TCKN is 15 or 16 characters; a shorter run carries at most 8 bytes. */
    static final int MIN_RUN = 12;
    static final int MAX_DEPTH = 2;
    static final int MAX_DECODED = 2 * 1024 * 1024;
    static final int BLOB_LIMIT = 256;
    static final double ENTROPY_LIMIT = 4.5;

    private static final int MAX_EXPANSION = 4;
    private static final double[] C_LOG_C = new double[BLOB_LIMIT + 1];

    static {
        for (int c = 2; c <= BLOB_LIMIT; c++) {
            C_LOG_C[c] = c * Math.log(c) / Math.log(2);
        }
    }

    /** Findings inside decoded layers and the non-verdict reason, if any; {@code stops} when the scan was cut short. */
    record Outcome(List<Finding> findings, String reason, boolean stops) {
        static final Outcome NONE = new Outcome(List.of(), null, false);
    }

    private final DetectorSet detectors;
    private final List<Finding> findings = new ArrayList<>();
    private long decoded;
    private String reason;
    private boolean stop;

    private Base64Layers(DetectorSet detectors) {
        this.detectors = detectors;
    }

    /** Inspects the base64 layers of one normalised field. */
    static Outcome inspect(String normalised, DetectorSet detectors) {
        Base64Layers layers = new Base64Layers(detectors);
        layers.scan(normalised, 0);
        if (layers.reason == null && layers.findings.isEmpty()) {
            return Outcome.NONE;
        }
        return new Outcome(layers.findings, layers.reason, layers.stop);
    }

    /** {@code depth} is the number of decodes that produced {@code text}. */
    private void scan(String text, int depth) {
        int n = text.length();
        int i = 0;
        StringBuilder run = new StringBuilder();
        while (i < n && !stop) {
            if (value(text.charAt(i)) < 0) {
                i++;
                continue;
            }
            run.setLength(0);
            while (i < n) {
                char c = text.charAt(i);
                if (value(c) >= 0) {
                    run.append(c);
                    i++;
                } else if (c == '\r' || c == '\n') {
                    int j = i;
                    while (j < n && j - i < 2 && (text.charAt(j) == '\r' || text.charAt(j) == '\n')) {
                        j++;
                    }
                    if (j < n && value(text.charAt(j)) >= 0) {
                        i = j;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            int pad = 0;
            while (i < n && pad < 2 && text.charAt(i) == '=') {
                pad++;
                i++;
            }
            if (run.length() >= MIN_RUN) {
                examine(run.toString(), depth);
            }
        }
    }

    private void examine(String run, int depth) {
        byte[] bytes = decode(run);
        if (bytes != null) {
            decoded += bytes.length;
            if (decoded > MAX_DECODED) {
                halt("UNDECODABLE_BLOB");
                return;
            }
            if (fileMagic(bytes, run.length())) {
                flag("EMBEDDED_FILE");
                return;
            }
            String strict = BodyInspector.strictUtf8(bytes, bytes.length);
            if (strict != null) {
                layer(strict, depth);
                return;
            }
            // D-02: bytes that are binary only because of NUL or invalid bytes still reach the detectors (as UTF-16LE,
            // without NUL, or with replacement characters) before any blob decision. NUL padding can make random bytes
            // pass as text, so a recovered layer is still subject to the blob rule below.
            String recovered = recovered(bytes);
            if (recovered != null) {
                layer(recovered, depth);
            } else {
                scanLayer(new String(withoutNul(bytes), StandardCharsets.UTF_8), depth);
            }
            if (stop) {
                return;
            }
            if (recovered == null && realign(run, depth)) {
                return;
            }
        } else if (realign(run, depth)) {
            return;
        }
        if (!stop && run.length() > BLOB_LIMIT && entropy(run) > ENTROPY_LIMIT) {
            flag("UNDECODABLE_BLOB");
        }
    }

    /** A decoded text layer is scanned; a readable third layer is also a residual blob at any length (D-02). */
    private void layer(String text, int depth) {
        if (depth >= MAX_DEPTH && printable(text)) {
            flag("UNDECODABLE_BLOB");
        }
        scanLayer(text, depth);
    }

    private void scanLayer(String text, int depth) {
        String normalised = Normaliser.normalise(text);
        if (normalised.length() > MAX_EXPANSION * text.length() + 64) {
            halt("NORMALISATION");
            return;
        }
        findings.addAll(detectors.scan(normalised));
        if (DetectorSet.overLimit(findings)) {
            halt("FINDING_LIMIT");
            return;
        }
        if (depth < MAX_DEPTH) {
            scan(normalised, depth + 1);
        }
    }

    /**
     * D-03: a run glued to a prefix ({@code -}, {@code /}, a URL path, a word) decodes misaligned. Retries the run without
     * its leading {@code - _ + /}, each {@code /}-separated segment, and offsets 1 to 3; a retry counts only when it
     * decodes to text or a file signature. At most six decodes per run character, so the scan stays linear.
     *
     * @return true when the whole run, less its prefix, decoded (a segment alone never exempts the run from the blob rule)
     */
    private boolean realign(String run, int depth) {
        String stripped = stripLeading(run);
        boolean covered = !stripped.equals(run) && retry(stripped, depth);
        if (run.indexOf('/') >= 0) {
            int from = 0;
            for (int k = 0; k <= run.length() && !stop; k++) {
                if (k == run.length() || run.charAt(k) == '/') {
                    retry(stripLeading(run.substring(from, k)), depth);
                    from = k + 1;
                }
            }
        }
        for (int offset = 1; offset <= 3 && !covered && !stop; offset++) {
            if (stripped.length() - offset >= MIN_RUN) {
                covered = retry(stripped.substring(offset), depth);
            }
        }
        return covered;
    }

    private boolean retry(String candidate, int depth) {
        if (candidate.length() < MIN_RUN || stop) {
            return false;
        }
        byte[] bytes = decode(candidate);
        if (bytes == null) {
            return false;
        }
        boolean magic = fileMagic(bytes, candidate.length());
        String text = magic ? null : text(bytes);
        if (!magic && (text == null || !printable(text))) {
            return false;
        }
        decoded += bytes.length;
        if (decoded > MAX_DECODED) {
            halt("UNDECODABLE_BLOB");
        } else if (magic) {
            flag("EMBEDDED_FILE");
        } else {
            layer(text, depth);
        }
        return true;
    }

    /** A soft reason: remembered, and the scan goes on so findings after it are still made (D-01). */
    private void flag(String r) {
        if (reason == null) {
            reason = r;
        }
    }

    /** A hard reason: the scan stops. */
    private void halt(String r) {
        reason = r;
        stop = true;
    }

    /** Decoded bytes as text: strict UTF-8, UTF-16LE when every other byte is mostly NUL, or UTF-8 without NUL bytes. */
    static String text(byte[] b) {
        String strict = BodyInspector.strictUtf8(b, b.length);
        return strict != null ? strict : recovered(b);
    }

    /** Text that is not strict UTF-8 only because of NUL bytes: UTF-16LE or UTF-8 once NUL is removed; else null. */
    static String recovered(byte[] b) {
        if (utf16le(b)) {
            String s = new String(b, StandardCharsets.UTF_16LE);
            if (s.indexOf('\uFFFD') < 0) {
                return withoutNulChars(s);
            }
        }
        byte[] stripped = withoutNul(b);
        return stripped.length == b.length || stripped.length == 0 ? null
            : BodyInspector.strictUtf8(stripped, stripped.length);
    }

    private static boolean utf16le(byte[] b) {
        if (b.length < 4 || b.length % 2 != 0) {
            return false;
        }
        int zeros = 0;
        for (int k = 1; k < b.length; k += 2) {
            if (b[k] == 0) {
                zeros++;
            }
        }
        return zeros * 2 >= b.length / 2;
    }

    private static byte[] withoutNul(byte[] b) {
        int n = 0;
        for (byte x : b) {
            if (x != 0) {
                n++;
            }
        }
        if (n == b.length) {
            return b;
        }
        byte[] out = new byte[n];
        int o = 0;
        for (byte x : b) {
            if (x != 0) {
                out[o++] = x;
            }
        }
        return out;
    }

    private static String withoutNulChars(String s) {
        if (s.indexOf('\0') < 0) {
            return s;
        }
        StringBuilder out = new StringBuilder(s.length());
        for (int k = 0; k < s.length(); k++) {
            if (s.charAt(k) != '\0') {
                out.append(s.charAt(k));
            }
        }
        return out.toString();
    }

    /** Text a person or a model would read: no control character other than tab and line ends. */
    static boolean printable(String s) {
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f || c == '\uFFFD') {
                return false;
            }
        }
        return true;
    }

    private static String stripLeading(String run) {
        int k = 0;
        while (k < run.length() && "-_+/".indexOf(run.charAt(k)) >= 0) {
            k++;
        }
        return k == 0 ? run : run.substring(k);
    }

    /** Standard and URL-safe alphabets together; -1 for any other character. */
    static int value(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+' || c == '-') {
            return 62;
        }
        if (c == '/' || c == '_') {
            return 63;
        }
        return -1;
    }

    /** Decodes a run of alphabet characters (padding already stripped); null when its length cannot be base64. */
    static byte[] decode(CharSequence run) {
        int n = run.length();
        if (n % 4 == 1) {
            return null;
        }
        byte[] out = new byte[(int) ((long) n * 3 / 4)];
        int o = 0;
        int acc = 0;
        int bits = 0;
        for (int k = 0; k < n; k++) {
            acc = (acc << 6) | value(run.charAt(k));
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[o++] = (byte) (acc >> bits);
                acc &= (1 << bits) - 1;
            }
        }
        return out;
    }

    /**
     * The highest Shannon entropy, in bits per character, over any window of {@code min(length, BLOB_LIMIT)} characters
     * of an ASCII run, so low-entropy padding cannot dilute a high-entropy part (D-02). One pass with a running sum.
     */
    static double entropy(CharSequence run) {
        int n = run.length();
        int w = Math.min(n, BLOB_LIMIT);
        if (w == 0) {
            return 0;
        }
        int[] counts = new int[128];
        double sum = 0;
        for (int k = 0; k < w; k++) {
            sum = count(counts, sum, run.charAt(k), 1);
        }
        double logW = Math.log(w) / Math.log(2);
        double best = logW - sum / w;
        for (int k = w; k < n; k++) {
            sum = count(counts, sum, run.charAt(k - w), -1);
            sum = count(counts, sum, run.charAt(k), 1);
            best = Math.max(best, logW - sum / w);
        }
        return best;
    }

    private static double count(int[] counts, double sum, char c, int delta) {
        int i = c & 0x7f;
        double next = sum - C_LOG_C[counts[i]];
        counts[i] += delta;
        return next + C_LOG_C[counts[i]];
    }

    /**
     * Document, archive and compression signatures at any size (four bytes or a framed three); image (PNG, JPEG, GIF,
     * WebP) and zlib signatures, which a short opaque token can hit by chance, only in a run above {@link #BLOB_LIMIT}.
     */
    static boolean fileMagic(byte[] b, int runLength) {
        if (b.length < 3) {
            return false;
        }
        if (BodyInspector.binaryMagic(b, b.length) && !ContentDecoding.compressed(b, b.length)) {
            return true;
        }
        int b0 = b[0] & 0xff;
        int b1 = b[1] & 0xff;
        if (b0 == 0x1f && b1 == 0x8b && b[2] == 8) {
            return true;
        }
        if (runLength <= BLOB_LIMIT) {
            return false;
        }
        boolean png = b.length >= 4 && b0 == 0x89 && b1 == 'P' && b[2] == 'N' && b[3] == 'G';
        boolean jpeg = b0 == 0xff && b1 == 0xd8 && (b[2] & 0xff) == 0xff;
        boolean gif = b.length >= 4 && b0 == 'G' && b1 == 'I' && b[2] == 'F' && b[3] == '8';
        boolean webp = b.length >= 12 && b0 == 'R' && b1 == 'I' && b[2] == 'F' && b[3] == 'F'
            && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P';
        return png || jpeg || gif || webp || ContentDecoding.compressed(b, b.length);
    }
}
