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
 * A second Tomcat connector for the data plane's internal routes ({@code /internal/**}, port 8092). The internal routes
 * answer only on it and the admin routes never do: each side sees the other as 404, before Spring Security runs. An
 * internal body must declare its length; {@link BodyLimitFilter} bounds it to {@link #MAX_BODY_BYTES} as it is read.
 */
@Configuration(proxyBeanMethods = false)
public class InternalConnector {

    public static final String INTERNAL_PREFIX = "/internal/";
    public static final long MAX_BODY_BYTES = 2L * 1024 * 1024;

    private final Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> internalConnectorCustomizer(ControlProperties properties) {
        return factory -> {
            connector.setPort(properties.captureSink().port());
            connector.setProperty("address", properties.captureSink().bindAddress());
            connector.setMaxPostSize(0);
            factory.addAdditionalConnectors(connector);
        };
    }

    /** The bound port (the configured one, or the ephemeral one when configured as 0 in tests). */
    public int port() {
        return connector.getLocalPort();
    }

    @Bean
    FilterRegistrationBean<OncePerRequestFilter> internalPortFilter() {
        FilterRegistrationBean<OncePerRequestFilter> registration = new FilterRegistrationBean<>(new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
                boolean internalRoute = request.getRequestURI().startsWith(INTERNAL_PREFIX);
                boolean internalPort = request.getLocalPort() == port();
                if (internalRoute != internalPort) {
                    response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                    return;
                }
                if (internalRoute && "POST".equals(request.getMethod())) {
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
