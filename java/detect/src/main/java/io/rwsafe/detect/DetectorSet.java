package io.rwsafe.detect;

import io.rwsafe.platform.verdict.Finding;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** The Tier-1 detectors run together over one normalised text; at most {@link #MAX_FINDINGS} findings are kept. */
public final class DetectorSet {

    public static final int MAX_FINDINGS = 1000;

    private final List<Detector> detectors;

    public DetectorSet(List<Detector> detectors) {
        this.detectors = List.copyOf(detectors);
    }

    public static DetectorSet standard() {
        return new DetectorSet(List.of(new SecretDetector(), new TcknDetector(), new IbanDetector(), new CardDetector()));
    }

    /**
     * Findings sorted by start offset; overlaps are kept (the redactor merges them). Every detector runs; when the total
     * reaches {@link #MAX_FINDINGS} the scan stops and {@link #overLimit} is true for the result, which the caller turns
     * into a non-verdict rather than a partial redaction (PR 11 review D-01).
     */
    public List<Finding> scan(String normalisedText) {
        List<Finding> out = new ArrayList<>();
        for (Detector d : detectors) {
            d.scan(normalisedText, out);
            if (out.size() >= MAX_FINDINGS) {
                break;
            }
        }
        out.sort(Comparator.comparingInt(Finding::start));
        return out;
    }

    /** True when a scan hit the finding limit, so some text may be unscanned. */
    public static boolean overLimit(List<Finding> findings) {
        return findings.size() >= MAX_FINDINGS;
    }
}
