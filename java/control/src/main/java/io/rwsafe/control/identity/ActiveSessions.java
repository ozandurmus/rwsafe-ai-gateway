package io.rwsafe.control.identity;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * The signed-in sessions of this control-plane instance (PO decision Q-47, Sessions screen). Sessions are the servlet
 * container's in-memory sessions (no Spring Session store), so this registry holds a reference to each one an accepted
 * sign-in opened, keyed by a random handle that is neither the session id nor derived from it; the handle is the only
 * name the API gives a session. Ending a session invalidates it: the next request of its browser is unauthenticated.
 * Nothing here is logged; the client address is never recorded.
 */
@Component
public class ActiveSessions implements HttpSessionListener {

    static final String HANDLE = ActiveSessions.class.getName() + ".handle";

    /** One signed-in session; the login name stays in memory for the administrator's list and is never logged. */
    public record Entry(String handle, String loginName, String source, Set<String> roles, Instant signedInAt,
                        boolean passwordChangePending, HttpSession session) {

        /** The last request of the session, or empty when it has just ended. */
        public Optional<Instant> lastActivity() {
            try {
                return Optional.of(Instant.ofEpochMilli(session.getLastAccessedTime()));
            } catch (IllegalStateException ended) {
                return Optional.empty();
            }
        }

        @Override
        public String toString() {
            return "Entry[" + source + ", " + roles + "]";
        }
    }

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    /** Records a session an accepted sign-in opened. */
    public void register(HttpSession session, AuthenticatedUser user, Set<String> roles) {
        String handle = UUID.randomUUID().toString();
        session.setAttribute(HANDLE, handle);
        entries.put(handle, new Entry(handle, user.loginName(), user.source(), Set.copyOf(roles), Instant.now(),
            user.passwordChangeRequired(), session));
    }

    /** The session's password change is done. */
    public void passwordChanged(HttpSession session) {
        handle(session).ifPresent(h -> entries.computeIfPresent(h, (k, e) -> new Entry(e.handle(), e.loginName(),
            e.source(), e.roles(), e.signedInAt(), false, e.session())));
    }

    public Optional<String> handle(HttpSession session) {
        if (session == null) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable((String) session.getAttribute(HANDLE));
        } catch (IllegalStateException ended) {
            return Optional.empty();
        }
    }

    /** The live sessions, the latest sign-in first. */
    public List<Entry> list() {
        List<Entry> live = new ArrayList<>();
        for (Entry e : entries.values()) {
            if (e.lastActivity().isPresent()) {
                live.add(e);
            } else {
                entries.remove(e.handle());
            }
        }
        live.sort(Comparator.comparing(Entry::signedInAt).reversed());
        return live;
    }

    /** A live session by its handle; an expired one is dropped and not found. */
    public Optional<Entry> find(String handle) {
        Entry e = handle == null ? null : entries.get(handle);
        if (e != null && e.lastActivity().isEmpty()) {
            entries.remove(handle, e);
            return Optional.empty();
        }
        return Optional.ofNullable(e);
    }

    /**
     * Ends one session: removes it from the registry (atomically, so two callers cannot both end it) and invalidates
     * it; the entry is returned only when a live session was actually ended (PR 48 review D-06).
     */
    public Optional<Entry> end(String handle) {
        Entry e = handle == null ? null : entries.remove(handle);
        if (e == null) {
            return Optional.empty();
        }
        try {
            e.session().invalidate();
            return Optional.of(e);
        } catch (IllegalStateException alreadyEnded) {
            return Optional.empty();
        }
    }

    /** Ends every session of one local user (after it is disabled, its password reset or its roles changed). */
    public int endAll(String loginName, String source) {
        return endAllExcept(loginName, source, null);
    }

    /** Ends every session of one user but {@code keep} (its other sessions after an own password change, D-02). */
    public int endAllExcept(String loginName, String source, String keep) {
        int ended = 0;
        for (Entry e : List.copyOf(entries.values())) {
            if (e.source().equals(source) && !e.handle().equals(keep) && e.loginName().toLowerCase(Locale.ROOT)
                .equals(loginName.toLowerCase(Locale.ROOT)) && end(e.handle()).isPresent()) {
                ended++;
            }
        }
        return ended;
    }

    /**
     * Ends every session from one source but {@code keep} (PR 50 review D-08: the directory was switched off or its
     * group roles changed, so every directory session signs in again under the new settings).
     */
    public int endSource(String source, String keep) {
        int ended = 0;
        for (Entry e : List.copyOf(entries.values())) {
            if (e.source().equals(source) && !e.handle().equals(keep) && end(e.handle()).isPresent()) {
                ended++;
            }
        }
        return ended;
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        handle(event.getSession()).ifPresent(entries::remove);
    }
}
