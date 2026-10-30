package io.rwsafe.control.config;

import io.rwsafe.persistence.Database;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/**
 * Migrates at start (Recreate rollout, PORTS_AND_RESOURCES) and exposes the persistence module. ADR-002 §1-§2: Flyway
 * runs as the migrate role ({@code rwsafe_migrate}, the schema owner) and the application queries as the DML role
 * ({@code rwsafe_app}, {@code spring.datasource.*}). The migrate credential is {@code rwsafe.migration.username}
 * ({@code RWSAFE_DB_MIGRATE_USER}) and the config-tree file {@code rwsafe.migration.password}; without a username (local
 * runs and tests) the application's own data source migrates.
 */
@Configuration(proxyBeanMethods = false)
public class PersistenceConfig {

    @Bean
    Database database(DataSource dataSource, @Value("${spring.datasource.url}") String url,
                      @Value("${rwsafe.migration.username:${RWSAFE_DB_MIGRATE_USER:}}") String migrateUser,
                      @Value("${rwsafe.migration.password:}") String migratePassword) {
        return Database.migrateAndOpen(migrationDataSource(dataSource, url, migrateUser, migratePassword), dataSource);
    }

    /**
     * The data source Flyway runs on: the migrate role's when a username is configured, otherwise the application's.
     * A configured username without its password refuses to start (fail closed, never a silent fall back to the
     * application role).
     */
    static DataSource migrationDataSource(DataSource application, String url, String user, String password) {
        if (user == null || user.isBlank()) {
            return application;
        }
        if (password == null || password.isBlank()) {
            throw new IllegalStateException("rwsafe.migration.username is set but the migrate role's password file "
                + "(rwsafe.migration.password) is missing or empty");
        }
        DriverManagerDataSource migrate = new DriverManagerDataSource(url, user.strip(), password.strip());
        migrate.setDriverClassName("org.postgresql.Driver");
        return migrate;
    }
}
