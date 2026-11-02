package io.rwsafe.control.identity;

import java.util.Set;

/**
 * The result of a successful bind.
 *
 * @param source                 {@code ldap}, {@code local} (break-glass) or {@code local_user} (PO decision Q-47)
 * @param passwordChangeRequired a local user signed in with a generated password and must set a new one first
 */
public record AuthenticatedUser(String loginName, Set<String> roles, String source, boolean passwordChangeRequired) {

    public AuthenticatedUser {
        roles = Set.copyOf(roles);
    }

    public AuthenticatedUser(String loginName, Set<String> roles, String source) {
        this(loginName, roles, source, false);
    }

    /** Never prints the login name. */
    @Override
    public String toString() {
        return "AuthenticatedUser[" + source + ", " + roles + "]";
    }
}
