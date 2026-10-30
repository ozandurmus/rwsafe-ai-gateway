package io.rwsafe.control.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Three more Tomcat connectors (PORTS_AND_RESOURCES §3): the capture sink (8092) serves the ingestion route
 * ({@code /internal/v1/verdict-events}), the snapshot feed (8091) serves the policy snapshot
 * ({@code /internal/v1/policy/**}, POLICY_SNAPSHOT_CONTRACT), and the metrics listener (9400) serves only
 * {@code GET /metrics} (Prometheus text, fixed labels only). Each internal route answers only on its own connector and
 * the admin routes only on the admin port: everything else is 404, before Spring Security runs. An internal body must
 * declare its length; {@link BodyLimitFilter} bounds it to {@link #MAX_BODY_BYTES} as it is read.
 */
@Configuration(proxyBeanMethods = false)
public class InternalConnector {

    public static final String INTERNAL_PREFIX = "/internal/";
    public static final String SNAPSHOT_PREFIX = "/internal/v1/policy/";
    public static final long MAX_BODY_BYTES = 2L * 1024 * 1024;
    public static final String METRICS_PATH = "/metrics";

    private final Connector captureSink = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
    private final Connector snapshotFeed = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
    private final Connector metrics = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);

    /**
     * The metrics listener is {@code rwsafe.metrics.port} / {@code rwsafe.metrics.bind-address} (RWSAFE_METRICS_PORT,
     * RWSAFE_METRICS_BIND; loopback 9400 by default, the pod address in the deploy).
     */
    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> internalConnectorCustomizer(ControlProperties properties,
            @Value("${rwsafe.metrics.port:9400}") int metricsPort,
            @Value("${rwsafe.metrics.bind-address:127.0.0.1}") String metricsBind) {
        return factory -> {
            metrics.setPort(metricsPort);
            metrics.setProperty("address", metricsBind);
            metrics.setMaxPostSize(0);
            factory.addAdditionalConnectors(metrics);
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

    /** The metrics listener's bound port. */
    public int metricsPort() {
        return metrics.getLocalPort();
    }

    /**
     * True when the three additional listeners (capture sink, snapshot feed, metrics) are bound and started (the
     * readiness endpoint; the admin listener answers the probe itself, and the migrations ran before the context, and so
     * any listener, came up). PR 27 review D-04: the metrics listener counts too.
     */
    public boolean listening() {
        return started(captureSink) && started(snapshotFeed) && started(metrics);
    }

    private static boolean started(Connector connector) {
        return connector.getState() == LifecycleState.STARTED && connector.getLocalPort() > 0;
    }

    /**
     * True when {@code method} {@code uri} may be served on {@code localPort}. The metrics listener serves
     * {@code GET /metrics} and nothing else (PR 27 review D-04).
     */
    boolean routeAllowed(String method, String uri, int localPort) {
        boolean internalRoute = uri.startsWith(INTERNAL_PREFIX);
        boolean snapshotRoute = uri.startsWith(SNAPSHOT_PREFIX);
        boolean metricsRoute = uri.equals(METRICS_PATH);
        if (localPort == metricsPort()) {
            return metricsRoute && "GET".equals(method);
        }
        if (localPort == snapshotPort()) {
            return snapshotRoute;
        }
        if (localPort == port()) {
            return internalRoute && !snapshotRoute;
        }
        return !internalRoute && !metricsRoute;
    }

    @Bean
    FilterRegistrationBean<OncePerRequestFilter> internalPortFilter() {
        FilterRegistrationBean<OncePerRequestFilter> registration = new FilterRegistrationBean<>(new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
                if (!routeAllowed(request.getMethod(), request.getRequestURI(), request.getLocalPort())) {
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
