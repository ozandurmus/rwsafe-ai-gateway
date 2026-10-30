package io.rwsafe.policy;

import java.util.List;
import java.util.Locale;

/**
 * One platform-matrix row as the engine needs it: vendor-published host suffixes, which of them are API or sign-in hosts
 * (docs/product/PLATFORM_MATRIX.md section 2).
 */
public record PlatformRule(String platform, List<String> hostSuffixes, List<String> apiHosts, List<String> loginHosts) {

    public PlatformRule {
        hostSuffixes = List.copyOf(hostSuffixes);
        apiHosts = List.copyOf(apiHosts);
        loginHosts = List.copyOf(loginHosts);
    }

    boolean matches(String host) {
        return matchesAny(host, hostSuffixes);
    }

    static boolean matchesAny(String host, List<String> suffixes) {
        String h = host.toLowerCase(Locale.ROOT);
        for (String suffix : suffixes) {
            if (h.equals(suffix) || h.endsWith("." + suffix)) {
                return true;
            }
        }
        return false;
    }
}
