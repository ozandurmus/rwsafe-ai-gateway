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

    /** Findings sorted by start offset; overlaps are kept (the redactor merges them). */
    public List<Finding> scan(String normalisedText) {
        List<Finding> out = new ArrayList<>();
        for (Detector d : detectors) {
            d.scan(normalisedText, out);
            if (out.size() >= MAX_FINDINGS) {
                break;
            }
        }
        out.sort(Comparator.comparingInt(Finding::start));
        return out.size() > MAX_FINDINGS ? List.copyOf(out.subList(0, MAX_FINDINGS)) : out;
    }
}
