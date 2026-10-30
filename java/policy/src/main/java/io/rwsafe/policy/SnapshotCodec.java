package io.rwsafe.policy;

import io.rwsafe.platform.verdict.DataClass;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads a signed policy snapshot body (docs/architecture/POLICY_SNAPSHOT_CONTRACT.md) into a {@link PolicySnapshot}. Any
 * deviation from the contract refuses the whole snapshot: a missing or unknown class, an unknown action, a fail-closed
 * class set to ALLOW or WARN in any scope, a stale or future issue time, an unknown format, and for format 2 a scoped rule
 * with an unknown or missing field, a duplicate id, an empty or oversized group list, or an unknown mode.
 */
public final class SnapshotCodec {

    public static final Duration MAX_AGE = Duration.ofHours(24);
    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    private static final int MAX_BODY = 1024 * 1024;
    /** Format 2 bounds (POLICY_SNAPSHOT_CONTRACT.md); the rule id bound is this codec's, see {@link #MAX_RULE_ID}. */
    private static final int MAX_SCOPED_RULES = 256;
    private static final int MAX_GROUPS_PER_RULE = 32;
    private static final int MAX_GROUP_NAME = 256;
    /** Rule ids travel on every verdict event; the contract names no bound, so this codec sets one. */
    public static final int MAX_RULE_ID = 128;
    private static final Set<String> SCOPED_RULE_FIELDS = Set.of("id", "groups", "mode", "classActions");

    /** Why a snapshot was refused; the reason is a short fixed token for metrics and events. */
    public static final class Rejected extends Exception {
        private static final long serialVersionUID = 1L;

        private final String reason;

        public Rejected(String reason) {
            super(reason, null, false, false);
            this.reason = reason;
        }

        public String reason() {
            return reason;
        }
    }

    private SnapshotCodec() {
    }

    public static PolicySnapshot parse(byte[] body, Instant now) throws Rejected {
        if (body.length > MAX_BODY) {
            throw new Rejected("TOO_LARGE");
        }
        Object root;
        try {
            root = Json.parse(body);
        } catch (Json.Invalid e) {
            throw new Rejected("MALFORMED");
        }
        Map<String, Object> m = object(root);
        Object format = m.get("format");
        boolean scoped = Long.valueOf(2).equals(format);
        if (!scoped && !Long.valueOf(1).equals(format)) {
            throw new Rejected("FORMAT");
        }
        // Format 1 is format 2 without scoped rules; the field belongs to format 2 only, where it is required.
        if (scoped != m.containsKey("scopedRules")) {
            throw new Rejected(scoped ? "SCOPE_FIELD" : "FORMAT");
        }
        long version = number(m.get("version"));
        if (version < 1) {
            throw new Rejected("VERSION");
        }
        String id = text(m.get("id"));
        Instant issuedAt;
        try {
            issuedAt = Instant.parse(text(m.get("issuedAt")));
        } catch (DateTimeParseException e) {
            throw new Rejected("ISSUED_AT");
        }
        if (issuedAt.isBefore(now.minus(MAX_AGE))) {
            throw new Rejected("STALE");
        }
        if (issuedAt.isAfter(now.plus(CLOCK_SKEW))) {
            throw new Rejected("FUTURE");
        }
        if (!(m.get("enforceFailClosed") instanceof Boolean enforce)) {
            throw new Rejected("MALFORMED");
        }
        Map<DataClass, Action> classActions = classActions(m.get("classActions"));
        if (classActions.size() != DataClass.values().length) {
            throw new Rejected("MISSING_CLASS");
        }
        List<PlatformRule> platforms = new ArrayList<>();
        for (Object o : list(m.get("platforms"))) {
            Map<String, Object> p = object(o);
            platforms.add(new PlatformRule(text(p.get("platform")), texts(p.get("hostSuffixes")),
                texts(p.get("apiHosts")), texts(p.get("loginHosts"))));
        }
        List<ScopedRule> scopedRules = scoped ? scopedRules(m.get("scopedRules")) : List.of();
        return new PolicySnapshot(version, id, classActions, enforce, platforms, issuedAt, scopedRules);
    }

    /**
     * A class-to-action map, complete (the {@code ANY} scope) or partial (a scoped rule). Fail-closed classes never take
     * ALLOW or WARN, in any scope and any mode (ADR-010 §1, §4, PR 14 review D-04, PO decision Q-39 item 4).
     */
    private static Map<DataClass, Action> classActions(Object o) throws Rejected {
        Map<DataClass, Action> out = new EnumMap<>(DataClass.class);
        for (Map.Entry<String, Object> e : object(o).entrySet()) {
            DataClass c;
            Action a;
            try {
                c = DataClass.valueOf(e.getKey());
                a = Action.valueOf(text(e.getValue()));
            } catch (IllegalArgumentException ex) {
                throw new Rejected("UNKNOWN_CLASS_OR_ACTION");
            }
            if (c.failClosed() && (a == Action.ALLOW || a == Action.WARN)) {
                throw new Rejected("FAIL_CLOSED_WEAKENED");
            }
            out.put(c, a);
        }
        return out;
    }

    /** Format 2 {@code scopedRules} (POLICY_SNAPSHOT_CONTRACT.md "Format 2: scoped rules"). */
    private static List<ScopedRule> scopedRules(Object o) throws Rejected {
        List<Object> entries = list(o);
        if (entries.size() > MAX_SCOPED_RULES) {
            throw new Rejected("SCOPE_TOO_MANY");
        }
        List<ScopedRule> out = new ArrayList<>(entries.size());
        Set<String> ids = new HashSet<>();
        for (Object entry : entries) {
            Map<String, Object> r = object(entry);
            if (!SCOPED_RULE_FIELDS.equals(r.keySet())) {
                throw new Rejected("SCOPE_FIELD");
            }
            String id = text(r.get("id"));
            if (id.length() > MAX_RULE_ID) {
                throw new Rejected("SCOPE_FIELD");
            }
            if (!ids.add(id)) {
                throw new Rejected("SCOPE_DUPLICATE_ID");
            }
            List<Object> rawGroups = list(r.get("groups"));
            if (rawGroups.isEmpty() || rawGroups.size() > MAX_GROUPS_PER_RULE) {
                throw new Rejected("SCOPE_GROUPS");
            }
            Set<String> groups = new HashSet<>();
            for (Object g : rawGroups) {
                if (!(g instanceof String name) || name.isBlank() || name.length() > MAX_GROUP_NAME) {
                    throw new Rejected("SCOPE_GROUPS");
                }
                groups.add(ScopedRule.normaliseGroup(name));
            }
            ScopedRule.Mode mode = switch (text(r.get("mode"))) {
                case "enforce" -> ScopedRule.Mode.ENFORCE;
                case "monitor" -> ScopedRule.Mode.MONITOR;
                default -> throw new Rejected("SCOPE_MODE");
            };
            out.add(new ScopedRule(id, groups, mode, classActions(r.get("classActions"))));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object o) throws Rejected {
        if (o instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        throw new Rejected("MALFORMED");
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o) throws Rejected {
        if (o instanceof List<?> l) {
            return (List<Object>) l;
        }
        throw new Rejected("MALFORMED");
    }

    private static String text(Object o) throws Rejected {
        if (o instanceof String str && !str.isBlank()) {
            return str;
        }
        throw new Rejected("MALFORMED");
    }

    private static long number(Object o) throws Rejected {
        if (o instanceof Long l) {
            return l;
        }
        throw new Rejected("MALFORMED");
    }

    private static List<String> texts(Object o) throws Rejected {
        List<String> out = new ArrayList<>();
        for (Object x : list(o)) {
            out.add(text(x));
        }
        return out;
    }
}
