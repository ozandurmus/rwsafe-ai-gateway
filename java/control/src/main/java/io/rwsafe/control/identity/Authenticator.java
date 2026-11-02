package io.rwsafe.control.identity;

import java.util.Optional;

/**
 * One authentication front (ARCHITECTURE.md §3.2 identity, CORPORATE_TECHNOLOGY_STACK: LDAP bind first, SAML 2.0 later
 * behind the same seam). Empty means "not authenticated here"; implementations never say why, so a caller cannot tell an
 * unknown name from a wrong password.
 */
public interface Authenticator {

    Optional<AuthenticatedUser> authenticate(String loginName, char[] password);

    /**
     * True when this front owns {@code loginName}: after it refuses the name, no later front is asked (a local user is
     * authoritative for its login name, PR 48 review D-04). Asked only after {@link #authenticate} refused.
     */
    default boolean authoritative(String loginName) {
        return false;
    }
}
