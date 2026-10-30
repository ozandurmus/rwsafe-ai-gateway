package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

/**
 * ADR-002 §1-§2 (PR 18 review D-06): Flyway migrates as {@code rwsafe_migrate}, the application works as
 * {@code rwsafe_app}, with the grants of the committed database start script {@code deploy/rwsafe/base/db/rwsafe-roles.sql}
 * run as it is in the pod. The application role reads and writes rows and cannot change the schema.
 */
class TwoRoleMigrationTest {

    private static final String HASH = "$2a$12$" + "y".repeat(53);

    @Test
    void flywayRunsAsTheMigrateRoleAndTheApplicationRoleHasDmlOnly() throws Exception {
        EmbeddedPostgres server = TestDatabase.server();
        String database = "rwsafe_two_roles";
        try (Connection c = server.getPostgresDatabase().getConnection(); Statement s = c.createStatement()) {
            s.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rwsafe_migrate') THEN "
                + "CREATE ROLE rwsafe_migrate LOGIN; END IF; END $$");
            s.execute("CREATE DATABASE " + database + " OWNER rwsafe_migrate");
        }
        try (Connection c = server.getDatabase("postgres", database).getConnection(); Statement s = c.createStatement()) {
            s.execute(Files.readString(rolesSql()));
        }
        DataSource migrate = server.getDatabase("rwsafe_migrate", database);
        DataSource app = server.getDatabase("rwsafe_app", database);

        Database db = Database.migrateAndOpen(migrate, app);

        try (Connection c = migrate.getConnection(); PreparedStatement q = c.prepareStatement(
            "SELECT DISTINCT tableowner FROM pg_tables WHERE schemaname = 'public'"); ResultSet r = q.executeQuery()) {
            r.next();
            assertEquals("rwsafe_migrate", r.getString(1), "every migrated table is owned by the migrate role");
            assertTrue(!r.next(), "no table has another owner");
        }
        assertTrue(db.reachable());
        assertTrue(db.localAccounts().createIfAbsent(new LocalAccount("breakglass", HASH, List.of("security_admin"), true),
            new AuditContext("system:bootstrap", "local_account.create", "FIRST_START", null)),
            "the application role writes rows, and the audit trigger writes its ledger row");
        try (Connection c = app.getConnection(); Statement s = c.createStatement()) {
            assertEquals("rwsafe_app", one(s, "SELECT current_user"));
            for (String ddl : new String[] {"CREATE TABLE synthetic_ddl (id int)", "DROP TABLE verdict_event",
                "ALTER TABLE local_account ADD COLUMN synthetic text", "TRUNCATE flyway_schema_history"}) {
                SQLException e = assertThrows(SQLException.class, () -> s.execute(ddl), ddl);
                assertTrue(e.getMessage().contains("permission denied") || e.getMessage().contains("must be owner"),
                    ddl + ": " + e.getMessage());
            }
        }
        // PR 23 D-11 / Q-SIEM-3: an application session idle inside a transaction is aborted after 60 s, so it cannot
        // hold the SIEM export's visibility barrier for longer.
        for (DataSource role : List.of(app, migrate)) {
            try (Connection c = role.getConnection(); Statement s = c.createStatement()) {
                assertEquals("1min", one(s, "SHOW idle_in_transaction_session_timeout"));
            }
        }
    }

    private static String one(Statement s, String sql) throws SQLException {
        try (ResultSet r = s.executeQuery(sql)) {
            r.next();
            return r.getString(1);
        }
    }

    /** The committed script, found from the working directory (Gradle runs the tests in the module directory). */
    private static Path rolesSql() {
        for (Path p = Path.of("").toAbsolutePath(); p != null; p = p.getParent()) {
            Path candidate = p.resolve("deploy/rwsafe/base/db/rwsafe-roles.sql");
            if (Files.isRegularFile(candidate) && Files.isRegularFile(p.resolve("AGENTS.md"))) {
                return candidate;
            }
        }
        throw new IllegalStateException("deploy/rwsafe/base/db/rwsafe-roles.sql not found above the working directory");
    }
}
