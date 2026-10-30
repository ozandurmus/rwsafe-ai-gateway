package io.rwsafe.policy;

import java.util.Locale;

/**
 * Classifies a request from its encapsulated HTTP headers into platform × surface × step (ICAP spec §4.3). Shape
 * fingerprints per flow arrive with the protocol fixtures of phase 0; this classifier uses host, method, content type
 * and user agent only.
 */
public final class FlowClassifier {

    private final PolicySnapshot snapshot;

    public FlowClassifier(PolicySnapshot snapshot) {
        this.snapshot = snapshot;
    }

    public Flow classify(String host, String method, String contentType, String userAgent) {
        String h = host == null ? "" : stripPort(host);
        for (PlatformRule rule : snapshot.platforms()) {
            if (rule.matches(h)) {
                return new Flow(rule.platform(), surface(rule, h, userAgent), step(rule, h, method, contentType));
            }
        }
        return new Flow("unknown", Flow.Surface.UNKNOWN, step(null, h, method, contentType));
    }

    private static Flow.Surface surface(PlatformRule rule, String host, String userAgent) {
        String ua = userAgent == null ? "" : userAgent.toLowerCase(Locale.ROOT);
        if (ua.contains("vscode") || ua.contains("jetbrains") || ua.contains("copilot")) {
            return Flow.Surface.IDE;
        }
        if (ua.contains("claude-cli") || ua.contains("codex")) {
            return Flow.Surface.CLI;
        }
        if (PlatformRule.matchesAny(host, rule.apiHosts())) {
            return Flow.Surface.API;
        }
        return Flow.Surface.WEB;
    }

    private static Flow.Step step(PlatformRule rule, String host, String method, String contentType) {
        if (rule != null && PlatformRule.matchesAny(host, rule.loginHosts())) {
            return Flow.Step.LOGIN;
        }
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (ct.startsWith("multipart/")) {
            return Flow.Step.UPLOAD;
        }
        if ("POST".equalsIgnoreCase(method) && (ct.contains("json") || ct.startsWith("text/"))) {
            return Flow.Step.CHAT;
        }
        return Flow.Step.OTHER;
    }

    private static String stripPort(String host) {
        int colon = host.lastIndexOf(':');
        return colon > 0 && host.indexOf(']') < colon ? host.substring(0, colon) : host;
    }
}
