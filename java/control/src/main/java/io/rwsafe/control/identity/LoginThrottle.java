package io.rwsafe.control.identity;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Brute-force throttling (PR 12 review D-04). Five failed logins for one name from one source within 15 minutes lock
 * that pair for 15 minutes, so a third party elsewhere cannot lock an administrator out with five guesses; fifty failures
 * for one name from any sources lock the name itself. A lock is never evicted early: entries are dropped only when
 * their window and lock have passed, and when 10 000 live entries exist the throttle refuses every name it does not
 * know yet (fail closed) instead of forgetting a lock.
 */
public final class LoginThrottle {

    static final int MAX_PER_SOURCE = 5;
    static final int MAX_PER_NAME = 50;
    static final Duration WINDOW = Duration.ofMinutes(15);
    static final int MAX_ENTRIES = 10_000;

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
        State name = states.get(nameKey(loginName));
        State pair = states.get(pairKey(loginName, source));
        if ((name != null && name.locked(now)) || (pair != null && pair.locked(now))) {
            return true;
        }
        return pair == null && full(now);
    }

    public synchronized void failure(String loginName, String source) {
        Instant now = clock.instant();
        count(pairKey(loginName, source), MAX_PER_SOURCE, now);
        count(nameKey(loginName), MAX_PER_NAME, now);
    }

    /** A success clears the pair only; the name's count keeps running so one good login does not reset a spray. */
    public synchronized void success(String loginName, String source) {
        states.remove(pairKey(loginName, source));
    }

    private void count(String key, int max, Instant now) {
        State s = states.get(key);
        if (s == null || s.expired(now)) {
            if (s == null && full(now)) {
                return;
            }
            s = new State(0, now, null);
        }
        int failures = s.failures() + 1;
        states.put(key, new State(failures, s.first(), failures >= max ? now.plus(WINDOW) : s.lockedUntil()));
    }

    private boolean full(Instant now) {
        if (states.size() < MAX_ENTRIES) {
            return false;
        }
        states.values().removeIf(s -> s.expired(now));
        return states.size() >= MAX_ENTRIES;
    }

    private static String nameKey(String loginName) {
        return "n\u0000" + loginName.toLowerCase(Locale.ROOT);
    }

    private static String pairKey(String loginName, String source) {
        return "p\u0000" + loginName.toLowerCase(Locale.ROOT) + "\u0000" + (source == null ? "" : source);
    }
}
