package io.rwsafe.control;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Entry point of the {@code rwsafe-control} image (control-plane role, ARCHITECTURE.md §3.2). Flyway and jOOQ are driven
 * by {@code io.rwsafe.persistence.Database}, the only migration and query path. Spring Boot 4 keeps their
 * auto-configurations in modules this application does not use; they stay excluded by name so a later dependency cannot
 * switch them on. The generated in-memory user is off, since the identity package is the only authentication path.
 */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class, excludeName = {
    "org.springframework.boot.jooq.autoconfigure.JooqAutoConfiguration",
    "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"})
@ConfigurationPropertiesScan
@EnableScheduling
public class ControlApplication {

    public static void main(String[] args) {
        SpringApplication.run(ControlApplication.class, args);
    }
}
