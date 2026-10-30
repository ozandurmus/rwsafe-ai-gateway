package io.rwsafe.policy;

import io.rwsafe.platform.verdict.DataClass;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Reads a signed policy snapshot body (docs/architecture/POLICY_SNAPSHOT_CONTRACT.md) into a {@link PolicySnapshot}. Any
 * deviation from the contract refuses the whole snapshot: a missing or unknown class, an unknown action, a fail-closed
 * class set to ALLOW or WARN, a stale or future issue time, an unknown format.
 */
public final class SnapshotCodec {

    public static final Duration MAX_AGE = Duration.ofHours(24);
    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    private static final int MAX_BODY = 1024 * 1024;

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
        if (!Long.valueOf(1).equals(m.get("format"))) {
            throw new Rejected("FORMAT");
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
        Map<String, Object> actions = object(m.get("classActions"));
        Map<DataClass, Action> classActions = new EnumMap<>(DataClass.class);
        for (Map.Entry<String, Object> e : actions.entrySet()) {
            DataClass c;
            Action a;
            try {
                c = DataClass.valueOf(e.getKey());
                a = Action.valueOf(text(e.getValue()));
            } catch (IllegalArgumentException ex) {
                throw new Rejected("UNKNOWN_CLASS_OR_ACTION");
            }
            // ADR-010 §1, §4: fail-closed classes have no monitor-only relaxation, in any snapshot (PR 14 review D-04).
            if (c.failClosed() && (a == Action.ALLOW || a == Action.WARN)) {
                throw new Rejected("FAIL_CLOSED_WEAKENED");
            }
            classActions.put(c, a);
        }
        if (classActions.size() != DataClass.values().length) {
            throw new Rejected("MISSING_CLASS");
        }
        List<PlatformRule> platforms = new ArrayList<>();
        for (Object o : list(m.get("platforms"))) {
            Map<String, Object> p = object(o);
            platforms.add(new PlatformRule(text(p.get("platform")), texts(p.get("hostSuffixes")),
                texts(p.get("apiHosts")), texts(p.get("loginHosts"))));
        }
        return new PolicySnapshot(version, id, classActions, enforce, platforms, issuedAt);
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
