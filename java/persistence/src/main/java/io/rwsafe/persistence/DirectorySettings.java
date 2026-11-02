package io.rwsafe.persistence;

import java.time.Instant;
import java.util.List;

/**
 * One directory settings version (V12). {@code bindPasswordSealed} is the AES-GCM sealed bind password or null when none
 * is set; nothing in this module can open it. URLs, distinguished names and group names are directory identifiers, so
 * {@link #toString()} prints none of them.
 *
 * @param version    0 for a version not stored yet (the store assigns the next one)
 * @param changeKind {@code seed}, {@code connection} or {@code group_roles}
 * @param tlsMode    {@code ldaps}, {@code starttls} or {@code none} (loopback only)
 */
public record DirectorySettings(int version, Instant createdAt, String createdBy, String changeKind, String reason,
                                boolean enabled, List<String> urls, String tlsMode, String caCertificatePem,
                                String bindDn, byte[] bindPasswordSealed, String userSearchBase,
                                String userSearchFilter, String groupAttribute, String groupSearchBase,
                                String groupSearchFilter, int connectTimeoutMs, int responseTimeoutMs,
                                List<GroupRoles> groupRoles) {

    /** One binding: the group's name as the administrator entered it, and the roles it grants. */
    public record GroupRoles(String group, List<String> roles) {

        public GroupRoles {
            roles = List.copyOf(roles);
        }

        /** Never prints the group name. */
        @Override
        public String toString() {
            return "GroupRoles[" + roles + "]";
        }
    }

    public DirectorySettings {
        urls = List.copyOf(urls);
        groupRoles = List.copyOf(groupRoles);
        bindPasswordSealed = bindPasswordSealed == null ? null : bindPasswordSealed.clone();
    }

    @Override
    public byte[] bindPasswordSealed() {
        return bindPasswordSealed == null ? null : bindPasswordSealed.clone();
    }

    /** The same settings under another version kind, actor and reason (a save copies the version it builds on). */
    public DirectorySettings as(String changeKind, String createdBy, String reason) {
        return new DirectorySettings(0, null, createdBy, changeKind, reason, enabled, urls, tlsMode, caCertificatePem,
            bindDn, bindPasswordSealed, userSearchBase, userSearchFilter, groupAttribute, groupSearchBase,
            groupSearchFilter, connectTimeoutMs, responseTimeoutMs, groupRoles);
    }

    /** The same settings with other group -> role bindings. */
    public DirectorySettings withGroups(List<GroupRoles> groups) {
        return new DirectorySettings(version, createdAt, createdBy, changeKind, reason, enabled, urls, tlsMode,
            caCertificatePem, bindDn, bindPasswordSealed, userSearchBase, userSearchFilter, groupAttribute,
            groupSearchBase, groupSearchFilter, connectTimeoutMs, responseTimeoutMs, groups);
    }

    /** Never prints an identifier, the sealed password or the reason. */
    @Override
    public String toString() {
        return "DirectorySettings[v" + version + ", " + changeKind + ", enabled=" + enabled + ", urls=" + urls.size()
            + ", tls=" + tlsMode + ", password=" + (bindPasswordSealed != null) + ", groups=" + groupRoles.size() + "]";
    }
}
