package io.rwsafe.control.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.apache.catalina.connector.Connector;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Two more Tomcat connectors for the data plane's internal routes (PORTS_AND_RESOURCES): the capture sink (8092) serves
 * the ingestion route ({@code /internal/v1/verdict-events}) and the snapshot feed (8091) serves the policy snapshot
 * ({@code /internal/v1/policy/**}, POLICY_SNAPSHOT_CONTRACT). Each internal route answers only on its own connector and
 * the admin routes only on the admin port: everything else is 404, before Spring Security runs. An internal body must
 * declare its length; {@link BodyLimitFilter} bounds it to {@link #MAX_BODY_BYTES} as it is read.
 */
@Configuration(proxyBeanMethods = false)
public class InternalConnector {

    public static final String INTERNAL_PREFIX = "/internal/";
    public static final String SNAPSHOT_PREFIX = "/internal/v1/policy/";
    public static final long MAX_BODY_BYTES = 2L * 1024 * 1024;

    private final Connector captureSink = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
    private final Connector snapshotFeed = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> internalConnectorCustomizer(ControlProperties properties) {
        return factory -> {
            captureSink.setPort(properties.captureSink().port());
            captureSink.setProperty("address", properties.captureSink().bindAddress());
            captureSink.setMaxPostSize(0);
            snapshotFeed.setPort(properties.snapshotFeed().port());
            snapshotFeed.setProperty("address", properties.snapshotFeed().bindAddress());
            snapshotFeed.setMaxPostSize(0);
            factory.addAdditionalConnectors(captureSink, snapshotFeed);
        };
    }

    /** The capture sink's bound port (the configured one, or the ephemeral one when configured as 0 in tests). */
    public int port() {
        return captureSink.getLocalPort();
    }

    /** The snapshot feed's bound port. */
    public int snapshotPort() {
        return snapshotFeed.getLocalPort();
    }

    /** True when {@code uri} may be served on {@code localPort}. */
    boolean routeAllowed(String uri, int localPort) {
        boolean internalRoute = uri.startsWith(INTERNAL_PREFIX);
        boolean snapshotRoute = uri.startsWith(SNAPSHOT_PREFIX);
        if (localPort == snapshotPort()) {
            return snapshotRoute;
        }
        if (localPort == port()) {
            return internalRoute && !snapshotRoute;
        }
        return !internalRoute;
    }

    @Bean
    FilterRegistrationBean<OncePerRequestFilter> internalPortFilter() {
        FilterRegistrationBean<OncePerRequestFilter> registration = new FilterRegistrationBean<>(new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
                if (!routeAllowed(request.getRequestURI(), request.getLocalPort())) {
                    response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                    return;
                }
                if (request.getRequestURI().startsWith(INTERNAL_PREFIX) && "POST".equals(request.getMethod())) {
                    long length = request.getContentLengthLong();
                    if (length < 0) {
                        response.setStatus(HttpServletResponse.SC_LENGTH_REQUIRED);
                        return;
                    }
                }
                chain.doFilter(request, response);
            }
        });
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
