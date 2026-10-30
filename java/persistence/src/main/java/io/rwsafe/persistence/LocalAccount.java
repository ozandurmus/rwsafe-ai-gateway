package io.rwsafe.persistence;

import java.util.List;

/** A local break-glass account: the BCrypt hash only, never a password. */
public record LocalAccount(String accountName, String passwordHash, List<String> roles, boolean enabled) {

    public LocalAccount {
        roles = List.copyOf(roles);
    }

    /** Never prints the hash. */
    @Override
    public String toString() {
        return "LocalAccount[" + accountName + ", " + roles + ", enabled=" + enabled + "]";
    }
}
