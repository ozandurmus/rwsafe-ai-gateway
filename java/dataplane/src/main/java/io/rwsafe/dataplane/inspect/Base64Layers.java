package io.rwsafe.dataplane.inspect;

import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.Normaliser;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Base64 layer decoding of one field (OFF2-3, ICAP spec §3, BY-ENC-1, BY-ENC-2, BY-ENC-8). A linear scanner (no regular
 * expression) finds runs of the standard or URL-safe base64 alphabet, joined across single line breaks (MIME wrapping),
 * of at least {@link #MIN_RUN} characters, and decodes them up to {@link #MAX_DEPTH} layers deep and at most
 * {@link #MAX_DECODED} bytes per field. A run that decodes to strict UTF-8 is normalised, scanned and its own runs decoded
 * in turn. A run that does not decode cleanly is decoded at all four alignments (start offsets 0 to 3, each over its whole
 * remainder and trimmed to whole quanta), so a prefix or suffix of any characters cannot misalign it, and every reading
 * that is not strict UTF-8 goes through every byte view: UTF-8 with NUL removed and invalid sequences replaced, the same
 * with non-text quanta blanked, UTF-16LE and UTF-16BE (PR 17 recheck D-05, D-07; recheck 2 D-09).
 * Every decode and every view is charged to the per-field budget; views are never decoded further, and nothing inside
 * the second decoded layer is decoded (PR 17 recheck 2 D-10).
 *
 * <p>The outcome is the findings inside decoded layers (the caller replaces the whole field) and, when one applies, a
 * non-verdict reason; the findings are always kept with it (D-01):
 * <ul>
 *   <li>{@code EMBEDDED_FILE}: decoded bytes start with a document, archive or compression signature (any size), or an
 *       image signature in a run above {@link #BLOB_LIMIT} characters; the file pipeline (BY-FILE-*) is not built;</li>
 *   <li>{@code UNDECODABLE_BLOB}: a run above {@link #BLOB_LIMIT} characters that is not text and whose Shannon entropy,
 *       the highest over any {@link #BLOB_LIMIT}-character window, is over {@link #ENTROPY_LIMIT} bits per character; a
 *       genuine base64 run inside the second decoded layer ({@link #thirdLayer}); or the per-field decode budget is
 *       spent;</li>
 *   <li>{@code NORMALISATION} and {@code FINDING_LIMIT} as for the outer text; these and a spent budget stop the scan
 *       ({@link Outcome#stops()}), the others let the caller go on inspecting the rest of the body.</li>
 * </ul>
 * When several reasons occur the most severe is kept ({@link #worse}): a terminating one outranks {@code EMBEDDED_FILE}.
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

    /**
     * Findings inside decoded layers and the non-verdict reason, if any; {@code stops} when the scan was cut short;
     * {@code scans} counts the detector passes, so a test can prove the work is bounded.
     */
    record Outcome(List<Finding> findings, String reason, boolean stops, int scans) {
        static final Outcome NONE = new Outcome(List.of(), null, false, 0);
    }

    private final DetectorSet detectors;
    private final List<Finding> findings = new ArrayList<>();
    private long decoded;
    private String reason;
    private boolean stop;
    private int scans;

    private Base64Layers(DetectorSet detectors) {
        this.detectors = detectors;
    }

    /** Inspects the base64 layers of one normalised field. */
    static Outcome inspect(String normalised, DetectorSet detectors) {
        Base64Layers layers = new Base64Layers(detectors);
        layers.scan(normalised, 0);
        if (layers.reason == null && layers.findings.isEmpty() && layers.scans == 0) {
            return Outcome.NONE;
        }
        return new Outcome(layers.findings, layers.reason, layers.stop, layers.scans);
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
                examine(run.toString(), pad, depth);
            }
        }
    }

    private void examine(String run, int pad, int depth) {
        if (depth >= MAX_DEPTH) {
            // Recheck 2 D-10: the second decoded layer's own words and values are its content (scanned as text); only a
            // genuine base64 run in it is a third layer. Nothing is decoded at this depth.
            if (thirdLayer(run, pad)) {
                flag("UNDECODABLE_BLOB");
            }
            return;
        }
        Map<DataClass, List<Finding>> best = new EnumMap<>(DataClass.class);
        Reading whole = read(run, depth, best);
        // Clean: the whole run is text and whole quanta, its stripped padding counted.
        boolean clean = whole == Reading.TEXT && (run.length() + pad) % 4 == 0;
        if (whole != Reading.STOP && whole != Reading.FILE && !clean) {
            // D-07, recheck 2 D-09: a run that is not whole quanta of clean text is also read at all four alignments;
            // each alignment is decoded over its whole remainder (a final two or three characters give their bytes, as
            // unpadded base64 does) and trimmed to whole quanta (so a glued suffix cannot extend the value).
            alignments:
            for (int offset = 0; offset < 4; offset++) {
                String rest = run.substring(offset);
                String lenient = rest.length() % 4 == 1 ? rest.substring(0, rest.length() - 1) : rest;
                String trimmed = rest.substring(0, rest.length() / 4 * 4);
                String[] candidates = trimmed.equals(lenient) ? new String[] {lenient} : new String[] {lenient, trimmed};
                for (String candidate : candidates) {
                    if (candidate.length() < 2 || candidate.equals(run)) {
                        continue;
                    }
                    if (read(candidate, depth, best) == Reading.STOP) {
                        break alignments;
                    }
                }
            }
        }
        // D-08 (recheck 2): whatever stopped the run, what it found is kept.
        for (List<Finding> classFindings : best.values()) {
            findings.addAll(classFindings);
        }
        if (DetectorSet.overLimit(findings)) {
            halt("FINDING_LIMIT");
            return;
        }
        if (!stop && whole != Reading.TEXT && whole != Reading.FILE && run.length() > BLOB_LIMIT
            && entropy(run) > ENTROPY_LIMIT) {
            flag("UNDECODABLE_BLOB");
        }
    }

    /** What one decoding of a run turned out to be. */
    private enum Reading { INVALID, FILE, TEXT, BINARY, STOP }

    /**
     * Decodes one candidate. Strict UTF-8 is a text layer: scanned and its own runs decoded one layer deeper. Anything
     * else is read through the byte views of D-05 (recheck 2 D-10: views only for bytes that are not strict UTF-8, and a
     * view is never decoded further).
     */
    private Reading read(String candidate, int depth, Map<DataClass, List<Finding>> best) {
        if (stop) {
            return Reading.STOP;
        }
        byte[] bytes = decode(candidate);
        if (bytes == null) {
            return Reading.INVALID;
        }
        if (!charge(bytes.length)) {
            return Reading.STOP;
        }
        if (fileMagic(bytes, candidate.length())) {
            flag("EMBEDDED_FILE");
            return Reading.FILE;
        }
        String strict = BodyInspector.strictUtf8(bytes, bytes.length);
        if (strict != null) {
            scanView(strict, depth, best, true);
            return stop ? Reading.STOP : Reading.TEXT;
        }
        scanViews(bytes, depth, best);
        return stop ? Reading.STOP : Reading.BINARY;
    }

    /**
     * D-05: bytes that are not strict UTF-8 are read every way that could hide text, never one way chosen by a
     * heuristic: UTF-8 with NUL removed and invalid sequences replaced; the same with every three-byte quantum that is not
     * printable text blanked (bytes decoded from a glued prefix or suffix would otherwise touch the value and hide it from
     * a detector that needs a boundary, recheck 2 D-09); and UTF-16LE and UTF-16BE at both byte parities. Each view is
     * charged to the per-field budget and scanned by the detectors only.
     */
    private void scanViews(byte[] bytes, int depth, Map<DataClass, List<Finding>> best) {
        List<String> views = new ArrayList<>(6);
        views.add(new String(withoutNul(bytes), StandardCharsets.UTF_8));
        views.add(quantumMasked(bytes));
        for (int parity = 0; parity < 2; parity++) {
            if (bytes.length - parity >= 2) {
                views.add(new String(bytes, parity, bytes.length - parity, StandardCharsets.UTF_16LE));
                views.add(new String(bytes, parity, bytes.length - parity, StandardCharsets.UTF_16BE));
            }
        }
        for (String view : views) {
            if (stop || !charge(view.length())) {
                return;
            }
            scanView(view, depth, best, false);
        }
    }

    /**
     * Scans one decoded reading and, for a text layer, decodes its own runs one layer deeper. What this reading found,
     * its inner layers included, is merged into {@code best} per class (the most findings any reading of the run gave),
     * so the readings of one run never count one value twice; the merge happens before any limit stops the scan (D-08).
     */
    private void scanView(String text, int depth, Map<DataClass, List<Finding>> best, boolean recurse) {
        if (stop) {
            return;
        }
        scans++;
        String normalised = Normaliser.normalise(text);
        if (normalised.length() > MAX_EXPANSION * text.length() + 64) {
            halt("NORMALISATION");
            return;
        }
        List<Finding> found = new ArrayList<>(detectors.scan(normalised));
        if (recurse && depth < MAX_DEPTH && !DetectorSet.overLimit(found)) {
            int mark = findings.size();
            scan(normalised, depth + 1);
            List<Finding> inner = findings.subList(mark, findings.size());
            found.addAll(inner);
            inner.clear();
        }
        Map<DataClass, List<Finding>> byClass = new EnumMap<>(DataClass.class);
        for (Finding f : found) {
            byClass.computeIfAbsent(f.dataClass(), c -> new ArrayList<>()).add(f);
        }
        byClass.forEach((c, list) -> {
            if (list.size() > best.getOrDefault(c, List.of()).size()) {
                best.put(c, list);
            }
        });
        if (DetectorSet.overLimit(found)) {
            halt("FINDING_LIMIT");
        }
    }

    /**
     * Recheck 2 D-10, Q-1: a run inside the second decoded layer is a third layer only when it looks like real base64:
     * at least 16 characters with its padding, a valid length, zero unused bits in the last quantum, and both upper- and
     * lower-case letters. Words ("configuration", "musteri_numarasi") and detector values (an access key, a TCKN) are not.
     */
    static boolean thirdLayer(String run, int pad) {
        int n = run.length();
        if (n + pad < 16 || n % 4 == 1 || (pad > 0 && (n + pad) % 4 != 0)) {
            return false;
        }
        int last = value(run.charAt(n - 1));
        if ((n % 4 == 2 && (last & 0x0f) != 0) || (n % 4 == 3 && (last & 0x03) != 0)) {
            return false;
        }
        boolean upper = false;
        boolean lower = false;
        for (int k = 0; k < n; k++) {
            char c = run.charAt(k);
            upper |= c >= 'A' && c <= 'Z';
            lower |= c >= 'a' && c <= 'z';
        }
        return upper && lower;
    }

    /** Charges decoded bytes to the per-field budget; false (and a hard stop) when it is spent. */
    private boolean charge(int bytes) {
        decoded += bytes;
        if (decoded > MAX_DECODED) {
            halt("UNDECODABLE_BLOB");
            return false;
        }
        return true;
    }

    /**
     * D-06: when several reasons occur, the most severe is kept: a terminating reason (a blob, a limit) outranks
     * {@code EMBEDDED_FILE}. The scan goes on after a soft reason so findings after it are still made (D-01).
     */
    private void flag(String r) {
        reason = worse(reason, r);
    }

    /** A hard reason: the scan stops. */
    private void halt(String r) {
        reason = worse(reason, r);
        stop = true;
    }

    /** The more severe of two non-verdict reasons (null is none). */
    static String worse(String a, String b) {
        return severity(b) > severity(a) ? b : a;
    }

    private static int severity(String r) {
        if (r == null) {
            return 0;
        }
        return switch (r) {
            case "EMBEDDED_FILE" -> 1;
            case "UNDECODABLE_BLOB" -> 2;
            default -> 3;
        };
    }

    /** ASCII text of the bytes with every three-byte group that holds a byte other than printable ASCII blanked. */
    static String quantumMasked(byte[] b) {
        char[] out = new char[b.length];
        for (int q = 0; q < b.length; q += 3) {
            int end = Math.min(b.length, q + 3);
            boolean text = true;
            for (int k = q; k < end; k++) {
                int c = b[k] & 0xff;
                text &= (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r';
            }
            for (int k = q; k < end; k++) {
                out[k] = text ? (char) (b[k] & 0xff) : ' ';
            }
        }
        return new String(out);
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
