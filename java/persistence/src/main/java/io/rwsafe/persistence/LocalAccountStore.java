package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.util.List;
import java.util.Optional;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;

/** Local break-glass accounts; every mutation carries an {@link AuditContext} and is ledgered by the trigger. */
public final class LocalAccountStore {

    private final DSLContext dsl;

    LocalAccountStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    public Optional<LocalAccount> find(String accountName) {
        return dsl.select(ACCOUNT_NAME, PASSWORD_HASH, ROLES, ENABLED).from(LOCAL_ACCOUNT)
            .where(ACCOUNT_NAME.eq(accountName))
            .fetchOptional(r -> new LocalAccount(r.get(ACCOUNT_NAME), r.get(PASSWORD_HASH), List.of(r.get(ROLES)),
                r.get(ENABLED)));
    }

    /** Creates the account unless one with that name exists; true when it was created. */
    public boolean createIfAbsent(LocalAccount account, AuditContext audit) {
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            return tx.insertInto(LOCAL_ACCOUNT, ACCOUNT_NAME, PASSWORD_HASH, ROLES, ENABLED)
                .values(account.accountName(), account.passwordHash(), account.roles().toArray(String[]::new),
                    account.enabled())
                .onConflict(ACCOUNT_NAME).doNothing().execute() == 1;
        });
    }
}
