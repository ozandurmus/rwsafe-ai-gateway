package io.rwsafe.control.identity;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Five failed logins for one name within 15 minutes lock that name for 15 minutes (SECURITY_REQUIREMENTS brute force).
 * Bounded memory: the oldest names are forgotten first beyond 10 000.
 */
public final class LoginThrottle {

    static final int MAX_FAILURES = 5;
    static final Duration WINDOW = Duration.ofMinutes(15);
    private static final int MAX_NAMES = 10_000;

    private record State(int failures, Instant first, Instant lockedUntil) {
    }

    private final Clock clock;
    private final Map<String, State> states = new LinkedHashMap<>(16, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, State> eldest) {
            return size() > MAX_NAMES;
        }
    };

    public LoginThrottle(Clock clock) {
        this.clock = clock;
    }

    public synchronized boolean locked(String loginName) {
        State s = states.get(key(loginName));
        return s != null && s.lockedUntil() != null && clock.instant().isBefore(s.lockedUntil());
    }

    public synchronized void failure(String loginName) {
        Instant now = clock.instant();
        String key = key(loginName);
        State s = states.get(key);
        if (s == null || now.isAfter(s.first().plus(WINDOW))) {
            s = new State(0, now, null);
        }
        int failures = s.failures() + 1;
        states.put(key, new State(failures, s.first(), failures >= MAX_FAILURES ? now.plus(WINDOW) : null));
    }

    public synchronized void success(String loginName) {
        states.remove(key(loginName));
    }

    private static String key(String loginName) {
        return loginName.toLowerCase(Locale.ROOT);
    }
}
