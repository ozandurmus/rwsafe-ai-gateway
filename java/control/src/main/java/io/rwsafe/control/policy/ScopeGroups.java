package io.rwsafe.control.policy;

import io.rwsafe.policy.GroupNames;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The group list of a scoped version (PO decision Q-39). Every name goes through the one shared normal form,
 * {@link GroupNames#normalise} in {@code java/policy}, which the data plane applies too; this class adds only the list
 * rules of POLICY_SNAPSHOT_CONTRACT format 2: 1 to 32 names, none twice after normalisation, sorted so the order the
 * operator typed them never changes the stored row or the snapshot bytes. Group names are operator data: nothing here
 * logs or echoes one.
 */
public final class ScopeGroups {

    public static final int MAX_GROUPS = 32;

    private ScopeGroups() {
    }

    /** The normal forms, sorted; null when the list is empty, longer than 32, has an invalid name or a duplicate. */
    public static List<String> normalise(List<String> raw) {
        if (raw == null || raw.isEmpty() || raw.size() > MAX_GROUPS) {
            return null;
        }
        Set<String> seen = new HashSet<>();
        for (String g : raw) {
            String n = GroupNames.normalise(g);
            if (n == null || !seen.add(n)) {
                return null;
            }
        }
        return seen.stream().sorted().toList();
    }

    /** True when every stored name is already in its normal form and the list is valid (the compiler's check). */
    public static boolean storedFormOk(List<String> stored) {
        List<String> n = normalise(stored);
        return n != null && n.equals(stored.stream().sorted().toList());
    }
}
