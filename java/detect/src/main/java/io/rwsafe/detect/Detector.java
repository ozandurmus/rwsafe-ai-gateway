package io.rwsafe.detect;

import io.rwsafe.platform.verdict.Finding;
import java.util.List;

/** A Tier-1 detector: linear-time scan of normalised text, appending findings (class and range only). */
public interface Detector {

    void scan(String text, List<Finding> out);
}
