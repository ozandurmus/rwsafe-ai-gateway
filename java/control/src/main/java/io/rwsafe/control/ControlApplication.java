package io.rwsafe.control;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.jooq.JooqAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Entry point of the {@code rwsafe-control} image (control-plane role, ARCHITECTURE.md §3.2). Flyway and jOOQ are driven
 * by {@code io.rwsafe.persistence.Database}, the only migration and query path, so Spring Boot's own wiring of both is off;
 * so is the generated in-memory user, since the identity package is the only authentication path.
 */
@SpringBootApplication(exclude = {FlywayAutoConfiguration.class, JooqAutoConfiguration.class,
    UserDetailsServiceAutoConfiguration.class})
@ConfigurationPropertiesScan
public class ControlApplication {

    public static void main(String[] args) {
        SpringApplication.run(ControlApplication.class, args);
    }
}
