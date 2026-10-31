package io.rwsafe.control.identity;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Brute-force throttling for one control-plane instance (PR 12 review D-04, N-01). Five failed logins for one name from
 * one client within 15 minutes lock that pair; twenty failures from one client, whatever the names, lock the client. No
 * lock spans clients, so nobody elsewhere can lock an administrator or the break-glass account out; the directory's own
 * account lockout covers guessing spread over many clients, and the break-glass password is a 24-character random value.
 * A lock is never evicted early. When 10 000 live entries exist, expired and then unlocked entries are dropped, never the
 * two entries the failure being counted needs (PR 43 review D-02: otherwise one key evicted the other on every attempt and
 * neither ever locked). If only locks remain, the throttle fails closed (AGENTS.md section 7): every login is refused for
 * one window, logged, rather than letting a failure go uncounted.
 */
public final class LoginThrottle {

    static final int MAX_PER_PAIR = 5;
    static final int MAX_PER_SOURCE = 20;
    static final Duration WINDOW = Duration.ofMinutes(15);
    static final int MAX_ENTRIES = 10_000;
    private static final Logger LOG = LoggerFactory.getLogger(LoginThrottle.class);

    private record State(int failures, Instant first, Instant lockedUntil) {

        boolean locked(Instant now) {
            return lockedUntil != null && now.isBefore(lockedUntil);
        }

        boolean expired(Instant now) {
            return !locked(now) && !now.isBefore(first.plus(WINDOW));
        }
    }

    private final Clock clock;
    private final int maxEntries;
    private final Map<String, State> states = new HashMap<>();
    private Instant saturatedUntil;

    public LoginThrottle(Clock clock) {
        this(clock, MAX_ENTRIES);
    }

    LoginThrottle(Clock clock, int maxEntries) {
        this.clock = clock;
        this.maxEntries = maxEntries;
    }

    public synchronized boolean locked(String loginName, String source) {
        Instant now = clock.instant();
        if (saturatedUntil != null && now.isBefore(saturatedUntil)) {
            return true;
        }
        State pair = states.get(pairKey(loginName, source));
        State client = states.get(sourceKey(source));
        return (pair != null && pair.locked(now)) || (client != null && client.locked(now));
    }

    public synchronized void failure(String loginName, String source) {
        Instant now = clock.instant();
        String pair = pairKey(loginName, source);
        String client = sourceKey(source);
        int needed = (states.containsKey(pair) ? 0 : 1) + (states.containsKey(client) ? 0 : 1);
        if (!room(now, needed, pair, client)) {
            saturatedUntil = now.plus(WINDOW);
            LOG.warn("login throttle full of live locks: every login is refused for one window");
            return;
        }
        count(pair, MAX_PER_PAIR, now);
        count(client, MAX_PER_SOURCE, now);
    }

    /** A success clears the pair only; the client's count keeps running so one good login does not reset a spray. */
    public synchronized void success(String loginName, String source) {
        states.remove(pairKey(loginName, source));
    }

    private void count(String key, int max, Instant now) {
        State s = states.get(key);
        if (s == null || s.expired(now)) {
            s = new State(0, now, null);
        }
        int failures = s.failures() + 1;
        states.put(key, new State(failures, s.first(), failures >= max ? now.plus(WINDOW) : s.lockedUntil()));
    }

    /** True when {@code needed} new entries fit, after dropping expired and then unlocked entries other than {@code keep}. */
    private boolean room(Instant now, int needed, String... keep) {
        java.util.Set<String> kept = java.util.Set.of(keep);
        if (states.size() + needed <= maxEntries) {
            return true;
        }
        states.entrySet().removeIf(e -> !kept.contains(e.getKey()) && e.getValue().expired(now));
        if (states.size() + needed <= maxEntries) {
            return true;
        }
        states.entrySet().removeIf(e -> !kept.contains(e.getKey()) && !e.getValue().locked(now));
        return states.size() + needed <= maxEntries;
    }

    private static String pairKey(String loginName, String source) {
        return "p\u0000" + loginName.toLowerCase(Locale.ROOT) + "\u0000" + (source == null ? "" : source);
    }

    private static String sourceKey(String source) {
        return "s\u0000" + (source == null ? "" : source);
    }
}
