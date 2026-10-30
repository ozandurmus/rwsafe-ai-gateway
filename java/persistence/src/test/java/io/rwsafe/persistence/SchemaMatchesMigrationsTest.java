package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Modifier;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.sql.DataSource;
import org.jooq.Field;
import org.junit.jupiter.api.Test;

/** The hand-written jOOQ schema names only columns the Flyway migrations create (there is no code generator). */
class SchemaMatchesMigrationsTest {

    @Test
    void everySchemaFieldExistsAfterTheMigrations() throws Exception {
        DataSource ds = TestDatabase.fresh();
        Database.migrateAndOpen(ds);
        int checked = 0;
        try (Connection c = ds.getConnection(); PreparedStatement q = c.prepareStatement(
            "SELECT count(*) FROM information_schema.columns WHERE table_name = ? AND column_name = ?")) {
            for (java.lang.reflect.Field member : Schema.class.getDeclaredFields()) {
                if (!Modifier.isStatic(member.getModifiers()) || !Field.class.isAssignableFrom(member.getType())) {
                    continue;
                }
                String[] name = ((Field<?>) member.get(null)).getQualifiedName().getName();
                q.setString(1, name[0]);
                q.setString(2, name[1]);
                try (ResultSet r = q.executeQuery()) {
                    r.next();
                    assertEquals(1, r.getInt(1), String.join(".", name) + " is not a migrated column");
                }
                checked++;
            }
        }
        assertTrue(checked > 20);
    }

    @Test
    void noColumnCanHoldABody() throws Exception {
        DataSource ds = TestDatabase.fresh();
        Database.migrateAndOpen(ds);
        try (Connection c = ds.getConnection(); PreparedStatement q = c.prepareStatement(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND (column_name LIKE '%body'"
                + " OR column_name LIKE '%prompt%' OR column_name LIKE '%content%' OR column_name LIKE '%claim%'"
                + " OR column_name LIKE '%address%')"); ResultSet r = q.executeQuery()) {
            r.next();
            assertEquals(0, r.getInt(1), "ADR-009: no body, raw claim or raw address column");
        }
    }
}
