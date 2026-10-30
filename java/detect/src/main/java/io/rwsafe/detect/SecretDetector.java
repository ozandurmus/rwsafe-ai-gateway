package io.rwsafe.detect;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import java.util.List;

/**
 * Credential shapes with a vendor prefix or a fixed frame, so a hit is high-confidence (RESPMOD uses the same set). RE2/J
 * only: linear in the input whatever the text (SR-DP-1).
 */
public final class SecretDetector implements Detector {

    private static final Pattern SECRETS = Pattern.compile(String.join("|",
        "\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b",
        "\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b",
        "\\bgithub_pat_[A-Za-z0-9_]{22,255}\\b",
        "\\bsk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_-]{20,}",
        "\\bAIza[0-9A-Za-z_-]{35}\\b",
        "\\bxox[abposr]-[A-Za-z0-9-]{10,}",
        "-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----",
        "\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"));

    @Override
    public void scan(String text, List<Finding> out) {
        Matcher m = SECRETS.matcher(text);
        while (m.find()) {
            if (out.size() >= DetectorSet.MAX_FINDINGS) {
                return;
            }
            out.add(new Finding(DataClass.SECRET, m.start(), m.end()));
        }
    }
}
