package io.rwsafe.control.policy;

import io.rwsafe.platform.verdict.DataClass;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The registry's fixed vocabulary (AGENTS.md section 6, ADR-008 §4, ADR-010) and its value checks. Rule ids are
 * {@code class.<CLASS>}, {@code platform.<id>} or {@code flow.ai-category}.
 */
public final class RegistryVocabulary {

    public static final String KIND_CLASS = "class_action";
    public static final String KIND_PLATFORM = "platform";
    public static final String KIND_FLOW = "flow";
    public static final String FLOW_RULE = "flow.ai-category";
    public static final List<String> ACTIONS = List.of("ALLOW", "WARN", "REDACT", "BLOCK");
    public static final List<String> MODES = List.of("monitor", "enforce");
    public static final List<String> STAGES = List.of("pilot", "pct25", "pct50", "all");
    /** The relaxing actions a fail-closed class never takes, in any version or snapshot (SR-DLP-1). */
    public static final Set<String> RELAXING_ACTIONS = Set.of("ALLOW", "WARN");
    public static final int MAX_HOSTS = 32;

    private RegistryVocabulary() {
    }

    /** The fail-closed classes (SR-DLP-1): every Tier-1 class today; the set is the platform's, with a test. */
    public static List<String> failClosedClasses() {
        return java.util.Arrays.stream(DataClass.values()).filter(DataClass::failClosed).map(Enum::name).toList();
    }

    public static boolean failClosedClass(String dataClass) {
        return failClosedClasses().contains(dataClass);
    }

    /** The kind a rule id names, or null when the id is not one the registry knows. */
    public static String kindOf(String ruleId) {
        if (ruleId == null) {
            return null;
        }
        if (ruleId.equals(FLOW_RULE)) {
            return KIND_FLOW;
        }
        if (ruleId.startsWith("class.") && dataClassOf(ruleId) != null) {
            return KIND_CLASS;
        }
        if (ruleId.startsWith("platform.") && platformId(ruleId.substring("platform.".length()))) {
            return KIND_PLATFORM;
        }
        return null;
    }

    /** {@code TCKN} for {@code class.TCKN}; null when the class is not a known one. */
    public static String dataClassOf(String ruleId) {
        String c = ruleId.substring("class.".length());
        for (DataClass d : DataClass.values()) {
            if (d.name().equals(c)) {
                return c;
            }
        }
        return null;
    }

    /** True when a rule may never take an exception: a fail-closed class or the fail-closed flow (ADR-010, PC-5). */
    public static boolean failClosedRule(String ruleId) {
        String kind = kindOf(ruleId);
        return KIND_FLOW.equals(kind) || (KIND_CLASS.equals(kind) && failClosedClass(dataClassOf(ruleId)));
    }

    /** The platform-matrix vocabulary: lower-case letters, digits, {@code -} and {@code _}, at most 64. */
    public static boolean platformId(String s) {
        if (s == null || s.isEmpty() || s.length() > 64 || !s.equals(s.toLowerCase(Locale.ROOT))) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
                return false;
            }
        }
        return Character.isLetterOrDigit(s.charAt(0));
    }

    /** A lower-case DNS name with at least two labels, never an address literal (the V2 column check, in Java). */
    public static boolean hostName(String h) {
        if (h == null || h.isEmpty() || h.length() > 253 || !h.contains(".")) {
            return false;
        }
        boolean allDigitsAndDots = true;
        for (String label : h.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
                    return false;
                }
                if (!(c >= '0' && c <= '9')) {
                    allDigitsAndDots = false;
                }
            }
        }
        return !allDigitsAndDots;
    }

    /** True when {@code host} is {@code suffix} or a subdomain of it (the data plane's matching rule). */
    public static boolean underSuffix(String host, String suffix) {
        return host.equals(suffix) || host.endsWith("." + suffix);
    }

    /** {@code SYNTHETIC_CHANGE}: an upper-case reason code, 3 to 64 characters. */
    public static boolean reasonCode(String s) {
        if (s == null || s.length() < 3 || s.length() > 64 || !(s.charAt(0) >= 'A' && s.charAt(0) <= 'Z')) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
                return false;
            }
        }
        return true;
    }
}
