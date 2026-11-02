package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.jooq.SelectField;
import org.jooq.impl.DSL;

/**
 * Directory settings versions (V12): append-only, the highest version is the active one. Every save inserts the next
 * version inside one transaction under an {@link AuditContext} (the trigger ledgers it under the version number and checks
 * that the row's actor is the ledger's), and only when the active version is still the one the caller built on, so two
 * administrators cannot overwrite each other's change unseen.
 */
public final class DirectorySettingsStore {

    /** The advisory lock of every settings save (any constant; one per database). */
    private static final long SETTINGS_LOCK = 0x7277_7361_6665_0c12L;

    private static final List<SelectField<?>> COLUMNS = List.of(DS_VERSION, DS_CREATED_AT, DS_CREATED_BY,
        DS_CHANGE_KIND, DS_REASON, DS_ENABLED, DS_URLS, DS_TLS_MODE, DS_CA_PEM, DS_BIND_DN, DS_BIND_PASSWORD_SEALED,
        DS_USER_SEARCH_BASE, DS_USER_SEARCH_FILTER, DS_GROUP_ATTRIBUTE, DS_GROUP_SEARCH_BASE, DS_GROUP_SEARCH_FILTER,
        DS_CONNECT_TIMEOUT, DS_RESPONSE_TIMEOUT, DS_GROUP_NAMES, DS_GROUP_ROLE_SETS);

    /** One history line: who saved which version, when, what kind of change and why. No setting value. */
    public record HistoryEntry(int version, java.time.Instant createdAt, String createdBy, String changeKind,
                               String reason) {

        @Override
        public String toString() {
            return "HistoryEntry[v" + version + ", " + changeKind + ", " + createdBy + "]";
        }
    }

    private final DSLContext dsl;

    DirectorySettingsStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    /** The active (highest) version, if any was ever saved. */
    public Optional<DirectorySettings> active() {
        return dsl.select(COLUMNS).from(DIRECTORY_SETTINGS).orderBy(DS_VERSION.desc()).limit(1)
            .fetchOptional(DirectorySettingsStore::settings);
    }

    /** The newest {@code limit} versions, newest first. */
    public List<HistoryEntry> history(int limit) {
        return dsl.select(DS_VERSION, DS_CREATED_AT, DS_CREATED_BY, DS_CHANGE_KIND, DS_REASON).from(DIRECTORY_SETTINGS)
            .orderBy(DS_VERSION.desc()).limit(limit)
            .fetch(r -> new HistoryEntry(r.get(DS_VERSION), r.get(DS_CREATED_AT), r.get(DS_CREATED_BY),
                r.get(DS_CHANGE_KIND), r.get(DS_REASON)));
    }

    /**
     * Inserts {@code next} as the version after {@code expectedVersion} (0: the table is empty).
     *
     * @throws DirectorySettingsConflict {@code DIRECTORY_SETTINGS_CHANGED} when another version was saved meanwhile
     */
    public DirectorySettings save(DirectorySettings next, int expectedVersion, AuditContext audit) {
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            tx.select(DSL.field("pg_advisory_xact_lock({0})", Object.class, DSL.val(SETTINGS_LOCK))).fetch();
            Integer latest = tx.select(DSL.max(DS_VERSION)).from(DIRECTORY_SETTINGS).fetchOne(0, Integer.class);
            int current = latest == null ? 0 : latest;
            if (current != expectedVersion) {
                throw new DirectorySettingsConflict("DIRECTORY_SETTINGS_CHANGED",
                    "The directory settings were changed meanwhile; reload them and save again.");
            }
            insert(tx, next, current + 1);
            return tx.select(COLUMNS).from(DIRECTORY_SETTINGS).where(DS_VERSION.eq(current + 1))
                .fetchOne(DirectorySettingsStore::settings);
        });
    }

    /** Inserts {@code seed} as version 1 when the table is empty (true), else changes nothing (false). */
    public boolean seedIfEmpty(DirectorySettings seed, AuditContext audit) {
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            tx.select(DSL.field("pg_advisory_xact_lock({0})", Object.class, DSL.val(SETTINGS_LOCK))).fetch();
            if (tx.fetchExists(DIRECTORY_SETTINGS)) {
                return false;
            }
            insert(tx, seed, 1);
            return true;
        });
    }

    private static void insert(DSLContext tx, DirectorySettings s, int version) {
        List<String> names = new ArrayList<>();
        List<String> roleSets = new ArrayList<>();
        for (DirectorySettings.GroupRoles g : s.groupRoles()) {
            names.add(g.group());
            roleSets.add(String.join(" ", g.roles()));
        }
        tx.insertInto(DIRECTORY_SETTINGS)
            .set(DS_VERSION, version)
            .set(DS_CREATED_BY, s.createdBy())
            .set(DS_CHANGE_KIND, s.changeKind())
            .set(DS_REASON, s.reason())
            .set(DS_ENABLED, s.enabled())
            .set(DS_URLS, s.urls().toArray(String[]::new))
            .set(DS_TLS_MODE, s.tlsMode())
            .set(DS_CA_PEM, s.caCertificatePem())
            .set(DS_BIND_DN, s.bindDn())
            .set(DS_BIND_PASSWORD_SEALED, s.bindPasswordSealed())
            .set(DS_USER_SEARCH_BASE, s.userSearchBase())
            .set(DS_USER_SEARCH_FILTER, s.userSearchFilter())
            .set(DS_GROUP_ATTRIBUTE, s.groupAttribute())
            .set(DS_GROUP_SEARCH_BASE, s.groupSearchBase())
            .set(DS_GROUP_SEARCH_FILTER, s.groupSearchFilter())
            .set(DS_CONNECT_TIMEOUT, s.connectTimeoutMs())
            .set(DS_RESPONSE_TIMEOUT, s.responseTimeoutMs())
            .set(DS_GROUP_NAMES, names.toArray(String[]::new))
            .set(DS_GROUP_ROLE_SETS, roleSets.toArray(String[]::new))
            .execute();
    }

    private static DirectorySettings settings(Record r) {
        String[] names = r.get(DS_GROUP_NAMES);
        String[] roleSets = r.get(DS_GROUP_ROLE_SETS);
        List<DirectorySettings.GroupRoles> groups = new ArrayList<>();
        for (int i = 0; i < names.length; i++) {
            groups.add(new DirectorySettings.GroupRoles(names[i], Arrays.asList(roleSets[i].split(" "))));
        }
        return new DirectorySettings(r.get(DS_VERSION), r.get(DS_CREATED_AT), r.get(DS_CREATED_BY),
            r.get(DS_CHANGE_KIND), r.get(DS_REASON), r.get(DS_ENABLED), List.of(r.get(DS_URLS)), r.get(DS_TLS_MODE),
            r.get(DS_CA_PEM), r.get(DS_BIND_DN), r.get(DS_BIND_PASSWORD_SEALED), r.get(DS_USER_SEARCH_BASE),
            r.get(DS_USER_SEARCH_FILTER), r.get(DS_GROUP_ATTRIBUTE), r.get(DS_GROUP_SEARCH_BASE),
            r.get(DS_GROUP_SEARCH_FILTER), r.get(DS_CONNECT_TIMEOUT), r.get(DS_RESPONSE_TIMEOUT), groups);
    }
}
