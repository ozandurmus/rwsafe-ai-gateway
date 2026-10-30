package io.rwsafe.persistence;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.conf.Settings;
import org.jooq.impl.DSL;

/** The control plane's PostgreSQL: Flyway is the only migration authority (Q-16), jOOQ the only query API. */
public final class Database {

    static {
        // jOOQ prints a logo and tips through its logger on first use; neither belongs in a product log.
        System.setProperty("org.jooq.no-logo", "true");
        System.setProperty("org.jooq.no-tips", "true");
    }

    private final DSLContext dsl;

    private Database(DataSource dataSource) {
        this.dsl = DSL.using(dataSource, SQLDialect.POSTGRES, new Settings().withExecuteLogging(false));
    }

    /** Applies the pending migrations from {@code db/migration}, then opens the query context, on one data source. */
    public static Database migrateAndOpen(DataSource dataSource) {
        return migrateAndOpen(dataSource, dataSource);
    }

    /**
     * ADR-002 §1-§2: applies the pending migrations as the migrate role ({@code migrate}, the schema owner), then opens
     * the query context on the application's DML role ({@code application}).
     */
    public static Database migrateAndOpen(DataSource migrate, DataSource application) {
        Flyway.configure()
            .dataSource(migrate)
            .locations("classpath:db/migration")
            .cleanDisabled(true)
            .validateMigrationNaming(true)
            .load()
            .migrate();
        return new Database(application);
    }

    DSLContext dsl() {
        return dsl;
    }

    public VerdictEventStore verdictEvents() {
        return new VerdictEventStore(dsl);
    }

    public VerdictQueries verdictQueries() {
        return new VerdictQueries(dsl);
    }

    public LocalAccountStore localAccounts() {
        return new LocalAccountStore(dsl);
    }

    public LoginRecordStore loginRecords() {
        return new LoginRecordStore(dsl);
    }

    public NoticeAcknowledgementStore noticeAcknowledgements() {
        return new NoticeAcknowledgementStore(dsl);
    }

    public PolicyRegistryStore policyRegistry() {
        return new PolicyRegistryStore(dsl);
    }

    public PolicySnapshotStore policySnapshots() {
        return new PolicySnapshotStore(dsl, policyRegistry());
    }

    /** True when a trivial query answers (health screen). */
    public boolean reachable() {
        try {
            return dsl.selectOne().fetchOne(0, Integer.class) == 1;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
