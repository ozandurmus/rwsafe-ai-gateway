package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.util.UUID;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;

/**
 * Accepted sign-ins (ARCHITECTURE.md §4.4): the actor's pseudonym, the source and whether the session is the masked
 * mode. Each row is ledgered by the audit trigger with the actor as its own audit actor.
 */
public final class LoginRecordStore {

    private final DSLContext dsl;

    LoginRecordStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    /** @param actorFingerprint {@code USR-<10 hex>} of the login name; {@code source} is {@code ldap} or {@code local} */
    public void record(String actorFingerprint, String source, boolean masked) {
        AuditContext audit = new AuditContext(actorFingerprint, masked ? "session.activate_masked" : "session.activate",
            source.equals("local") ? "BREAK_GLASS_LOGIN" : "DIRECTORY_LOGIN", UUID.randomUUID().toString());
        dsl.transaction(cfg -> {
            DSLContext tx = DSL.using(cfg);
            audit.apply(tx);
            tx.insertInto(LOGIN_RECORD, LOGIN_ACTOR, LOGIN_SOURCE, LOGIN_MASKED).values(actorFingerprint, source, masked)
                .execute();
        });
    }
}
