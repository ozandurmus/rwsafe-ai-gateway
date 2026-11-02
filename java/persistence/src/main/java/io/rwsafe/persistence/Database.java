package io.rwsafe.persistence;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
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
    private final String schemaVersion;

    private Database(DataSource dataSource, String schemaVersion) {
        this.dsl = DSL.using(dataSource, SQLDialect.POSTGRES, new Settings().withExecuteLogging(false));
        this.schemaVersion = schemaVersion;
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
        Flyway flyway = Flyway.configure()
            .dataSource(migrate)
            .locations("classpath:db/migration")
            .cleanDisabled(true)
            .validateMigrationNaming(true)
            .load();
        flyway.migrate();
        // Read once, as the migrate role, right after the migration: the application role need not read Flyway's table.
        MigrationInfo current = flyway.info().current();
        return new Database(application, current == null || current.getVersion() == null ? null
            : current.getVersion().getVersion());
    }

    /** The schema version Flyway reported after the start's migration (for example {@code 11}); null when unknown. */
    public String schemaVersion() {
        return schemaVersion;
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

    /** The C3 capture store: sealed records, the read ledger and deletion receipts (V8). */
    public CaptureStore captures() {
        return new CaptureStore(dsl);
    }

    public LocalAccountStore localAccounts() {
        return new LocalAccountStore(dsl);
    }

    /** Local users and administrator-ended sessions (V11). */
    public LocalUserStore localUsers() {
        return new LocalUserStore(dsl);
    }

    /** Directory settings versions and their group -> role bindings (V12). */
    public DirectorySettingsStore directorySettings() {
        return new DirectorySettingsStore(dsl);
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

    /** Read-only pages of the audit ledger (Administration -> Records). */
    public AuditLedgerQueries auditLedger() {
        return new AuditLedgerQueries(dsl);
    }

    public SiemExportStore siemExport() {
        return new SiemExportStore(dsl);
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
