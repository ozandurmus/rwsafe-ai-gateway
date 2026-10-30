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
 * A lock is never evicted early. When 10 000 live entries exist, unlocked entries are dropped first; if only locks remain,
 * a new failure is not recorded (logged) rather than refusing everyone.
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
    private final Map<String, State> states = new HashMap<>();

    public LoginThrottle(Clock clock) {
        this.clock = clock;
    }

    public synchronized boolean locked(String loginName, String source) {
        Instant now = clock.instant();
        State pair = states.get(pairKey(loginName, source));
        State client = states.get(sourceKey(source));
        return (pair != null && pair.locked(now)) || (client != null && client.locked(now));
    }

    public synchronized void failure(String loginName, String source) {
        Instant now = clock.instant();
        count(pairKey(loginName, source), MAX_PER_PAIR, now);
        count(sourceKey(source), MAX_PER_SOURCE, now);
    }

    /** A success clears the pair only; the client's count keeps running so one good login does not reset a spray. */
    public synchronized void success(String loginName, String source) {
        states.remove(pairKey(loginName, source));
    }

    private void count(String key, int max, Instant now) {
        State s = states.get(key);
        if (s == null || s.expired(now)) {
            if (s == null && !room(now)) {
                LOG.warn("login throttle full of live locks: a failure was not recorded");
                return;
            }
            s = new State(0, now, null);
        }
        int failures = s.failures() + 1;
        states.put(key, new State(failures, s.first(), failures >= max ? now.plus(WINDOW) : s.lockedUntil()));
    }

    /** True when a new entry fits, after dropping expired entries and then unlocked ones. */
    private boolean room(Instant now) {
        if (states.size() < MAX_ENTRIES) {
            return true;
        }
        states.values().removeIf(s -> s.expired(now));
        if (states.size() < MAX_ENTRIES) {
            return true;
        }
        states.values().removeIf(s -> !s.locked(now));
        return states.size() < MAX_ENTRIES;
    }

    private static String pairKey(String loginName, String source) {
        return "p\u0000" + loginName.toLowerCase(Locale.ROOT) + "\u0000" + (source == null ? "" : source);
    }

    private static String sourceKey(String source) {
        return "s\u0000" + (source == null ? "" : source);
    }
}
