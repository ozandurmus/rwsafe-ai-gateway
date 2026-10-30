package io.rwsafe.platform.enduser;

import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The deployment's values for the end-user texts ({@link EndUserCatalogue#CONFIGURED}): the data controller's name, the
 * data protection contact, the policy link and the retention figures. They come from the environment
 * ({@code RWSAFE_ENDUSER_<NAME>}, an uncommitted ConfigMap) and are never committed. An invalid value is dropped and
 * named in {@link #rejected()}, so a page renders without it (an optional paragraph is left out, the notice is
 * incomplete and has no version) instead of failing.
 */
public final class EndUserParameters {

    public static final String ENV_PREFIX = "RWSAFE_ENDUSER_";
    static final int MAX_LENGTH = 256;

    private final Map<String, String> values;
    private final Set<String> rejected;

    private EndUserParameters(Map<String, String> values, Set<String> rejected) {
        this.values = Collections.unmodifiableMap(values);
        this.rejected = Collections.unmodifiableSet(rejected);
    }

    public static EndUserParameters none() {
        return new EndUserParameters(new TreeMap<>(), new TreeSet<>());
    }

    /** Reads {@code RWSAFE_ENDUSER_CONTROLLER_NAME} and the other configured names from {@code env}. */
    public static EndUserParameters fromEnvironment(Map<String, String> env) {
        Map<String, String> named = new TreeMap<>();
        for (String name : EndUserCatalogue.CONFIGURED) {
            String value = env.get(environmentName(name));
            if (value != null) {
                named.put(name, value);
            }
        }
        return of(named);
    }

    /** {@code values} by placeholder name; a name outside {@link EndUserCatalogue#CONFIGURED} is refused. */
    public static EndUserParameters of(Map<String, String> values) {
        Map<String, String> accepted = new TreeMap<>();
        Set<String> rejected = new TreeSet<>();
        for (Map.Entry<String, String> e : values.entrySet()) {
            String name = e.getKey();
            if (!EndUserCatalogue.CONFIGURED.contains(name)) {
                throw new IllegalArgumentException("not a configured end-user parameter: " + name);
            }
            String value = e.getValue() == null ? "" : e.getValue().strip();
            if (value.isEmpty()) {
                continue;
            }
            if (valid(name, value)) {
                accepted.put(name, value);
            } else {
                rejected.add(name);
            }
        }
        return new EndUserParameters(accepted, rejected);
    }

    public static String environmentName(String name) {
        return ENV_PREFIX + name.toUpperCase(Locale.ROOT);
    }

    public Optional<String> get(String name) {
        return Optional.ofNullable(values.get(name));
    }

    /** The names of {@code needed} that have no accepted value. */
    public Set<String> missing(Set<String> needed) {
        Set<String> out = new TreeSet<>(needed);
        out.removeAll(values.keySet());
        return out;
    }

    /** Names whose configured value was refused (too long, a control character, a placeholder, a non-number). */
    public Set<String> rejected() {
        return rejected;
    }

    Map<String, String> asMap() {
        return values;
    }

    private static boolean valid(String name, String value) {
        if (value.length() > MAX_LENGTH || value.contains("{{") || value.contains("}}")) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                return false;
            }
        }
        if (name.startsWith("retention_")) {
            if (value.length() > 5) {
                return false;
            }
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
            }
            return value.charAt(0) != '0';
        }
        return true;
    }
}
