package io.rwsafe.persistence;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;

/** One embedded PostgreSQL 16 per test JVM; each caller gets a fresh, migrated database of its own. */
final class TestDatabase {

    private static final AtomicInteger SEQUENCE = new AtomicInteger();
    private static EmbeddedPostgres server;

    private TestDatabase() {
    }

    static synchronized DataSource fresh() {
        try {
            if (server == null) {
                server = EmbeddedPostgres.builder().start();
            }
            String name = "rwsafe_test_" + SEQUENCE.incrementAndGet();
            try (Connection c = server.getPostgresDatabase().getConnection(); Statement s = c.createStatement()) {
                s.execute("CREATE DATABASE " + name);
            }
            return server.getDatabase("postgres", name);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
