package io.rwsafe.control.identity;

import java.util.Set;

/** The MVP roles (MASKING_AND_PRIVACY B1); the rest of B1 arrives with the screens that need them. */
public final class Roles {

    public static final String SECURITY_ADMIN = "security_admin";
    public static final String VIEWER = "viewer";
    /** The masked role: every response passes the masking funnel. */
    public static final String REPLAY_VIEWER = "replay_viewer";
    public static final Set<String> ALL = Set.of(SECURITY_ADMIN, VIEWER, REPLAY_VIEWER);

    private Roles() {
    }

    public static String authority(String role) {
        return "ROLE_" + role;
    }
}
