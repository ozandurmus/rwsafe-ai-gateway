package io.rwsafe.control.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.rwsafe.control.api.ApiError;
import io.rwsafe.control.config.ControlProperties;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * The gate chain (ARCHITECTURE.md §3.2 rbac): session, CSRF, role, then the masking funnel for the masked role. Reads
 * need one of the three roles; every other API method needs {@code security_admin}, so the masked role is read-only.
 * The internal chain serves only the data plane's ingestion route, which the connector filter confines to port 8092.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain internalChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/internal/**")
            // Reachable only on the internal connector behind the namespace NetworkPolicy; mutual TLS replaces this
            // when the data plane gains its client certificate (Secure ICAP slice).
            .authorizeHttpRequests(a -> a.requestMatchers(HttpMethod.POST, "/internal/v1/verdict-events").permitAll()
                .anyRequest().denyAll())
            .csrf(c -> c.ignoringRequestMatchers("/internal/**"))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(c -> c.disable())
            .formLogin(f -> f.disable())
            .httpBasic(b -> b.disable())
            .logout(l -> l.disable());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain adminChain(HttpSecurity http, ControlProperties properties, ObjectMapper json) throws Exception {
        CookieCsrfTokenRepository csrfCookies = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfCookies.setCookieCustomizer(c -> c.sameSite("Strict").secure(properties.identity().cookieSecure()).path("/"));
        http.authorizeHttpRequests(a -> a
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/v1/auth/csrf").permitAll()
                .requestMatchers("/api/v1/auth/**").authenticated()
                .requestMatchers(HttpMethod.GET, "/api/v1/**")
                    .hasAnyRole(Roles.SECURITY_ADMIN, Roles.VIEWER, Roles.REPLAY_VIEWER)
                .requestMatchers("/api/**").hasRole(Roles.SECURITY_ADMIN)
                .requestMatchers(HttpMethod.GET, "/**").permitAll()
                .anyRequest().denyAll())
            .csrf(c -> c.csrfTokenRepository(csrfCookies).csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation(f -> f.changeSessionId()))
            .requestCache(c -> c.disable())
            .formLogin(f -> f.disable())
            .httpBasic(b -> b.disable())
            .logout(l -> l.disable())
            .headers(h -> h
                .contentSecurityPolicy(p -> p.policyDirectives("default-src 'self'; script-src 'self'; style-src 'self' "
                    + "'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; "
                    + "frame-ancestors 'none'"))
                .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                .frameOptions(f -> f.deny()))
            .exceptionHandling(e -> e
                .authenticationEntryPoint((request, response, ex) -> write(response, json,
                    HttpServletResponse.SC_UNAUTHORIZED, ApiError.of("AUTHENTICATION_REQUIRED", "Sign in first.")))
                .accessDeniedHandler((request, response, ex) -> write(response, json, HttpServletResponse.SC_FORBIDDEN,
                    ex instanceof CsrfException
                        ? ApiError.of("CSRF_TOKEN_INVALID", "The request lacks a valid CSRF token; reload the page.")
                        : ApiError.of("FORBIDDEN", "Your role does not allow this action."))));
        return http.build();
    }

    private static void write(HttpServletResponse response, ObjectMapper json, int status, ApiError error)
        throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        json.writeValue(response.getOutputStream(), error);
    }
}
