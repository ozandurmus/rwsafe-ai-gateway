package io.rwsafe.control.config;

import io.rwsafe.persistence.Database;
import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Migrates at start (Recreate rollout, PORTS_AND_RESOURCES) and exposes the persistence module. */
@Configuration(proxyBeanMethods = false)
public class PersistenceConfig {

    @Bean
    Database database(DataSource dataSource) {
        return Database.migrateAndOpen(dataSource);
    }
}
