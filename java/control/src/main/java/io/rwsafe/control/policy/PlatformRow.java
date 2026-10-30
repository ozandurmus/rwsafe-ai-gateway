package io.rwsafe.control.policy;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * One platform-matrix row as the snapshot carries it (POLICY_SNAPSHOT_CONTRACT {@code platforms}). The data plane takes
 * the first row whose suffix matches a host, so the rows' suffixes never overlap and the order of the rows never
 * changes a decision.
 */
public record PlatformRow(String platform, List<String> hostSuffixes, List<String> apiHosts, List<String> loginHosts) {

    public PlatformRow {
        hostSuffixes = List.copyOf(hostSuffixes);
        apiHosts = List.copyOf(apiHosts);
        loginHosts = List.copyOf(loginHosts);
    }

    /** The first defect of one row, as a sentence that names no host, or null. */
    String defect() {
        if (!RegistryVocabulary.platformId(platform)) {
            return "a platform id is not in the platform vocabulary";
        }
        if (hostSuffixes.isEmpty() || hostSuffixes.size() > RegistryVocabulary.MAX_HOSTS
            || apiHosts.size() > RegistryVocabulary.MAX_HOSTS || loginHosts.size() > RegistryVocabulary.MAX_HOSTS) {
            return "a row needs 1 to 32 host suffixes and at most 32 API and sign-in hosts";
        }
        for (List<String> hosts : List.of(hostSuffixes, apiHosts, loginHosts)) {
            if (!hosts.stream().allMatch(RegistryVocabulary::hostName) || new HashSet<>(hosts).size() != hosts.size()) {
                return "a host is not a lower-case DNS name (addresses are refused) or is repeated";
            }
        }
        for (String h : concat(apiHosts, loginHosts)) {
            if (hostSuffixes.stream().noneMatch(s -> RegistryVocabulary.underSuffix(h, s))) {
                return "an API or sign-in host is outside the row's host suffixes";
            }
        }
        return null;
    }

    /** The first defect of a whole set of rows (each row, repeated ids, overlapping suffixes), or null. */
    static String defect(List<PlatformRow> rows) {
        Set<String> ids = new HashSet<>();
        for (PlatformRow r : rows) {
            String d = r.defect();
            if (d != null) {
                return d;
            }
            if (!ids.add(r.platform())) {
                return "a platform id is repeated";
            }
        }
        for (PlatformRow a : rows) {
            for (PlatformRow b : rows) {
                if (a == b) {
                    continue;
                }
                for (String sa : a.hostSuffixes()) {
                    for (String sb : b.hostSuffixes()) {
                        if (RegistryVocabulary.underSuffix(sa, sb)) {
                            return "two platforms' host suffixes overlap, so the first match would depend on the order";
                        }
                    }
                }
            }
        }
        return null;
    }

    private static List<String> concat(List<String> a, List<String> b) {
        return java.util.stream.Stream.concat(a.stream(), b.stream()).toList();
    }
}
