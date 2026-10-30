package io.rwsafe.dataplane.inspect;

import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.Normaliser;
import io.rwsafe.platform.verdict.Finding;
import java.util.ArrayList;
import java.util.List;

/**
 * Base64 layer decoding of one field (OFF2-3, ICAP spec §3, BY-ENC-1, BY-ENC-2, BY-ENC-8). A linear scanner (no regular
 * expression) finds runs of the standard or URL-safe base64 alphabet, joined across single line breaks (MIME wrapping),
 * of at least {@link #MIN_RUN} characters, and decodes them up to {@link #MAX_DEPTH} layers deep and at most
 * {@link #MAX_DECODED} bytes per field. Decoded bytes that are strict UTF-8 are normalised and scanned, and their own runs
 * decoded in turn. The outcome is the findings inside decoded layers (the caller replaces the whole field) or a
 * non-verdict reason:
 * <ul>
 *   <li>{@code EMBEDDED_FILE}: decoded bytes start with a document, archive or compression signature (any size), or an
 *       image signature in a run above {@link #BLOB_LIMIT} characters; the file pipeline (BY-FILE-*) is not built;</li>
 *   <li>{@code UNDECODABLE_BLOB}: a run above {@link #BLOB_LIMIT} characters that is not readable text (it does not decode,
 *       decodes to binary, or is a third layer) and whose Shannon entropy is over {@link #ENTROPY_LIMIT} bits per
 *       character; or the per-field decode budget is spent;</li>
 *   <li>{@code NORMALISATION} and {@code FINDING_LIMIT} as for the outer text.</li>
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

    /** Findings inside decoded layers, or the non-verdict reason that stopped the field. */
    record Outcome(List<Finding> findings, String reason) {
        static final Outcome NONE = new Outcome(List.of(), null);
    }

    private final DetectorSet detectors;
    private final List<Finding> findings = new ArrayList<>();
    private long decoded;
    private String reason;

    private Base64Layers(DetectorSet detectors) {
        this.detectors = detectors;
    }

    /** Inspects the base64 layers of one normalised field. */
    static Outcome inspect(String normalised, DetectorSet detectors) {
        Base64Layers layers = new Base64Layers(detectors);
        layers.scan(normalised, 0);
        if (layers.reason != null) {
            return new Outcome(List.of(), layers.reason);
        }
        return layers.findings.isEmpty() ? Outcome.NONE : new Outcome(layers.findings, null);
    }

    /** {@code depth} is the number of decodes that produced {@code text}. */
    private void scan(String text, int depth) {
        int n = text.length();
        int i = 0;
        StringBuilder run = new StringBuilder();
        while (i < n && reason == null) {
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
                examine(run, depth);
            }
        }
    }

    private void examine(CharSequence run, int depth) {
        byte[] bytes = decode(run);
        if (bytes != null) {
            decoded += bytes.length;
            if (decoded > MAX_DECODED) {
                reason = "UNDECODABLE_BLOB";
                return;
            }
            if (fileMagic(bytes, run.length())) {
                reason = "EMBEDDED_FILE";
                return;
            }
            String text = depth < MAX_DEPTH ? BodyInspector.strictUtf8(bytes, bytes.length) : null;
            if (text != null) {
                String normalised = Normaliser.normalise(text);
                if (normalised.length() > MAX_EXPANSION * text.length() + 64) {
                    reason = "NORMALISATION";
                    return;
                }
                findings.addAll(detectors.scan(normalised));
                if (DetectorSet.overLimit(findings)) {
                    reason = "FINDING_LIMIT";
                    return;
                }
                scan(normalised, depth + 1);
                return;
            }
        }
        if (run.length() > BLOB_LIMIT && entropy(run) > ENTROPY_LIMIT) {
            reason = "UNDECODABLE_BLOB";
        }
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

    /** Shannon entropy in bits per character of an ASCII run. */
    static double entropy(CharSequence run) {
        int[] counts = new int[128];
        int n = run.length();
        for (int k = 0; k < n; k++) {
            counts[run.charAt(k) & 0x7f]++;
        }
        double h = 0;
        for (int c : counts) {
            if (c > 0) {
                double p = (double) c / n;
                h -= p * (Math.log(p) / Math.log(2));
            }
        }
        return h;
    }

    /**
     * Document, archive and compression signatures at any size (four bytes or a framed three); image and zlib signatures,
     * which a short opaque token can hit by chance, only in a run above {@link #BLOB_LIMIT}.
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
        return png || jpeg || gif || ContentDecoding.compressed(b, b.length);
    }
}
