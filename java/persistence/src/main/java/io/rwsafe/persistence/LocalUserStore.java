package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.jooq.impl.DSL;

/**
 * Local users (V11) and the sessions an administrator ended. Every mutation carries an {@link AuditContext} and is
 * ledgered by the trigger under the user's pseudonym. A change that would leave no enabled {@code security_admin} is
 * refused inside the same transaction, serialised by one advisory lock, so two administrators cannot each remove the
 * other at the same moment.
 */
public final class LocalUserStore {

    static final String SECURITY_ADMIN = "security_admin";
    /** The advisory lock of every change that may remove a security administrator (any constant; one per database). */
    private static final long ADMIN_LOCK = 0x7277_7361_6665_0b11L;

    private static final java.util.List<org.jooq.SelectField<?>> COLUMNS = List.of(LU_LOGIN, LU_SUBJECT, LU_DISPLAY,
        LU_HASH, LU_ROLES, LU_ENABLED, LU_MUST_CHANGE, LU_CREATED_AT, LU_UPDATED_AT, LU_PASSWORD_CHANGED_AT);

    private final DSLContext dsl;

    LocalUserStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    public List<LocalUser> list() {
        return dsl.select(COLUMNS).from(LOCAL_USER).orderBy(LU_CREATED_AT, LU_LOGIN).fetch(LocalUserStore::user);
    }

    /** @param loginName lower case, as stored */
    public Optional<LocalUser> find(String loginName) {
        return dsl.select(COLUMNS).from(LOCAL_USER).where(LU_LOGIN.eq(loginName)).fetchOptional(LocalUserStore::user);
    }

    /** @throws LocalUserConflict {@code LOCAL_USER_EXISTS} when the login name or its pseudonym is taken */
    public LocalUser create(LocalUser user, AuditContext audit) {
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            int inserted = tx.insertInto(LOCAL_USER, LU_LOGIN, LU_SUBJECT, LU_DISPLAY, LU_HASH, LU_ROLES, LU_ENABLED,
                    LU_MUST_CHANGE)
                .values(user.loginName(), user.subjectFingerprint(), user.displayName(), user.passwordHash(),
                    user.roles().toArray(String[]::new), user.enabled(), user.mustChangePassword())
                .onConflictDoNothing().execute();
            if (inserted != 1) {
                throw new LocalUserConflict("LOCAL_USER_EXISTS", "A local user with this login name exists.");
            }
            return tx.select(COLUMNS).from(LOCAL_USER).where(LU_LOGIN.eq(user.loginName()))
                .fetchOne(LocalUserStore::user);
        });
    }

    /**
     * Applies {@code change} to the stored user (display name, roles, enabled, hash, the change flag and its time; the
     * identity fields are fixed by the V11 guard) and returns the result. When the result would leave no enabled
     * {@code security_admin} among the local users, plus the enabled break-glass administrators when
     * {@code countBreakGlass}, it is refused with {@code LAST_SECURITY_ADMIN} and nothing changes.
     */
    public LocalUser update(String loginName, UnaryOperator<LocalUser> change, boolean countBreakGlass,
                            AuditContext audit) {
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            tx.select(DSL.field("pg_advisory_xact_lock({0})", Object.class, DSL.val(ADMIN_LOCK))).fetch();
            LocalUser before = tx.select(COLUMNS).from(LOCAL_USER).where(LU_LOGIN.eq(loginName)).forUpdate()
                .fetchOptional(LocalUserStore::user)
                .orElseThrow(() -> new LocalUserConflict("LOCAL_USER_NOT_FOUND", "No local user has this login name."));
            LocalUser after = change.apply(before);
            boolean wasAdmin = before.enabled() && before.roles().contains(SECURITY_ADMIN);
            boolean isAdmin = after.enabled() && after.roles().contains(SECURITY_ADMIN);
            if (wasAdmin && !isAdmin && enabledAdmins(tx, countBreakGlass) <= 1) {
                throw new LocalUserConflict("LAST_SECURITY_ADMIN",
                    "This change would leave no enabled security administrator; nothing changed.");
            }
            tx.update(LOCAL_USER)
                .set(LU_DISPLAY, after.displayName())
                .set(LU_HASH, after.passwordHash())
                .set(LU_ROLES, after.roles().toArray(String[]::new))
                .set(LU_ENABLED, after.enabled())
                .set(LU_MUST_CHANGE, after.mustChangePassword())
                .set(LU_PASSWORD_CHANGED_AT, after.passwordChangedAt())
                .where(LU_LOGIN.eq(loginName)).execute();
            return tx.select(COLUMNS).from(LOCAL_USER).where(LU_LOGIN.eq(loginName)).fetchOne(LocalUserStore::user);
        });
    }

    /** Enabled security administrators: the local users, and the enabled local (break-glass) accounts when asked. */
    public int enabledAdmins(boolean countBreakGlass) {
        return enabledAdmins(dsl, countBreakGlass);
    }

    private static int enabledAdmins(DSLContext tx, boolean countBreakGlass) {
        int users = tx.fetchCount(LOCAL_USER, LU_ENABLED.isTrue()
            .and(DSL.condition("{0} = ANY ({1})", DSL.val(SECURITY_ADMIN), LU_ROLES)));
        int accounts = countBreakGlass ? tx.fetchCount(LOCAL_ACCOUNT, ENABLED.isTrue()
            .and(DSL.condition("{0} = ANY ({1})", DSL.val(SECURITY_ADMIN), ROLES))) : 0;
        return users + accounts;
    }

    /**
     * Records that {@code endedBy} ended a session of {@code subject}; ledgered with the audit context, whose actor must
     * be {@code endedBy} (the V11 guard checks it).
     */
    public void recordSessionEnd(String subject, String endedBy, String source, AuditContext audit) {
        dsl.transaction(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            tx.insertInto(SESSION_END, SE_SUBJECT, SE_ENDED_BY, SE_SOURCE).values(subject, endedBy, source).execute();
        });
    }

    private static LocalUser user(Record r) {
        return new LocalUser(r.get(LU_LOGIN), r.get(LU_SUBJECT), r.get(LU_DISPLAY), r.get(LU_HASH),
            List.of(r.get(LU_ROLES)), r.get(LU_ENABLED), r.get(LU_MUST_CHANGE), r.get(LU_CREATED_AT),
            r.get(LU_UPDATED_AT), r.get(LU_PASSWORD_CHANGED_AT));
    }
}
