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
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * The gate chain (ARCHITECTURE.md §3.2 rbac): session, CSRF, role, then the masking funnel for the masked role. Reads
 * need one of the three roles; every other API method needs {@code security_admin}, so the masked role is read-only.
 * The internal chain serves only the internal routes, which the connector filter confines to their ports: the
 * ingestion route and the notice acknowledgement intake (8092) and the signed policy snapshot (8091).
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
                // Notice acknowledgements (C12) from the banner, IDE first run, directory import and credential issue.
                .requestMatchers(HttpMethod.POST, "/internal/v1/notice-acknowledgements").permitAll()
                // The signed snapshot: public content (class actions, vendor hosts), integrity by its Ed25519 signature.
                .requestMatchers(HttpMethod.GET, "/internal/v1/policy/snapshot").permitAll()
                .anyRequest().denyAll())
            .csrf(c -> c.ignoringRequestMatchers("/internal/**"))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(c -> c.disable())
            .formLogin(f -> f.disable())
            .httpBasic(b -> b.disable())
            .logout(l -> l.disable());
        return http.build();
    }

    /** One CSRF cookie repository, shared with the login controller so it can rotate the token (PR 12 review D-09). */
    @Bean
    CookieCsrfTokenRepository csrfTokenRepository(ControlProperties properties) {
        CookieCsrfTokenRepository csrfCookies = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfCookies.setCookieCustomizer(c -> c.sameSite("Strict").secure(properties.identity().cookieSecure()).path("/"));
        return csrfCookies;
    }

    @Bean
    @Order(2)
    SecurityFilterChain adminChain(HttpSecurity http, CookieCsrfTokenRepository csrfCookies, ObjectMapper json)
        throws Exception {
        http.authorizeHttpRequests(a -> a
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/v1/auth/csrf").permitAll()
                .requestMatchers("/api/v1/auth/**").authenticated()
                .requestMatchers(HttpMethod.GET, "/api/v1/**")
                    .hasAnyRole(Roles.SECURITY_ADMIN, Roles.PRIVACY_OFFICER, Roles.VIEWER, Roles.REPLAY_VIEWER)
                // A policy approval: either approver role, never a masked session; the service checks that the session
                // holds the role the approval is given in (AGENTS.md section 6).
                .requestMatchers(HttpMethod.POST, "/api/v1/policy/rules/*/versions/*/approvals")
                    .access((auth, context) -> new AuthorizationDecision(
                        (hasRole(auth.get(), Roles.SECURITY_ADMIN) || hasRole(auth.get(), Roles.PRIVACY_OFFICER))
                            && !hasRole(auth.get(), Roles.REPLAY_VIEWER)))
                // Mutations: security_admin, and never a masked session, whatever else it holds (PR 12 review D-02).
                .requestMatchers("/api/**").access((auth, context) -> new AuthorizationDecision(
                    hasRole(auth.get(), Roles.SECURITY_ADMIN) && !hasRole(auth.get(), Roles.REPLAY_VIEWER)))
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

    private static boolean hasRole(Authentication auth, String role) {
        return auth != null && auth.isAuthenticated() && auth.getAuthorities().stream()
            .anyMatch(a -> Roles.authority(role).equals(a.getAuthority()));
    }

    private static void write(HttpServletResponse response, ObjectMapper json, int status, ApiError error)
        throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        json.writeValue(response.getOutputStream(), error);
    }
}
