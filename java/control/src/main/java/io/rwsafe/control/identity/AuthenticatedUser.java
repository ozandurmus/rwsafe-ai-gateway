package io.rwsafe.control.identity;

import java.util.Set;

/**
 * The result of a successful bind.
 *
 * @param source {@code ldap} or {@code local}
 */
public record AuthenticatedUser(String loginName, Set<String> roles, String source) {

    public AuthenticatedUser {
        roles = Set.copyOf(roles);
    }
}
