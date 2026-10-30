package io.rwsafe.control.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/** PR 18 review D-01 (readiness before the listeners are up) and D-06 (Flyway's own credential), without a context. */
class ReadinessAndMigrationConfigTest {

    @Test
    void notReadyUntilTheInternalListenersHaveStarted() {
        InternalConnector internal = new InternalConnector();
        assertFalse(internal.listening(), "connectors that never started are not listening");
        assertEquals(503, new ReadinessController(internal).ready().getStatusCode().value());
    }

    @Test
    void flywayUsesTheMigrateRoleWhenOneIsConfigured() {
        DataSource app = new DriverManagerDataSource("jdbc:postgresql://127.0.0.1:5432/rwsafe", "rwsafe_app", "x");
        assertSame(app, PersistenceConfig.migrationDataSource(app, "jdbc:postgresql://127.0.0.1:5432/rwsafe", "", null),
            "local runs and tests migrate with the application's data source");
        String password = "synthetic-" + System.nanoTime();
        DataSource migrate = PersistenceConfig.migrationDataSource(app, "jdbc:postgresql://127.0.0.1:5432/rwsafe",
            "rwsafe_migrate", password + "\n");
        assertTrue(migrate instanceof DriverManagerDataSource);
        DriverManagerDataSource d = (DriverManagerDataSource) migrate;
        assertEquals("rwsafe_migrate", d.getUsername());
        assertEquals(password, d.getPassword(), "the config-tree file's trailing newline is not part of the password");
        assertEquals("jdbc:postgresql://127.0.0.1:5432/rwsafe", d.getUrl());
        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> PersistenceConfig.migrationDataSource(app, "jdbc:postgresql://127.0.0.1:5432/rwsafe", "rwsafe_migrate",
                " "));
        assertTrue(e.getMessage().contains("rwsafe.migration.password"), "fails closed, never falls back to the app role");
    }
}
