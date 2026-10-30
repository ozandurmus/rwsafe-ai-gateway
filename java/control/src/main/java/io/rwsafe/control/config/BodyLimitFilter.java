package io.rwsafe.control.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Bounds every request body by the bytes actually read, not only by the declared length (PR 12 review D-03): 2 MiB on
 * the internal ingestion route, 64 KiB on the admin API (its largest body is a login). A body that goes past its bound
 * fails the read with {@link BodyTooLargeException}, which the API maps to 413.
 */
@Configuration(proxyBeanMethods = false)
public class BodyLimitFilter {

    public static final long ADMIN_MAX_BYTES = 64L * 1024;

    /** The read went past the route's byte bound. */
    public static final class BodyTooLargeException extends IOException {

        private static final long serialVersionUID = 1L;

        BodyTooLargeException() {
            super("request body too large");
        }
    }

    @Bean
    FilterRegistrationBean<OncePerRequestFilter> bodyLimit() {
        FilterRegistrationBean<OncePerRequestFilter> registration = new FilterRegistrationBean<>(new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
                long limit = request.getRequestURI().startsWith(InternalConnector.INTERNAL_PREFIX)
                    ? InternalConnector.MAX_BODY_BYTES : ADMIN_MAX_BYTES;
                if (request.getContentLengthLong() > limit) {
                    response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
                    return;
                }
                chain.doFilter(new Bounded(request, limit), response);
            }
        });
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
        return registration;
    }

    private static final class Bounded extends HttpServletRequestWrapper {

        private final long limit;
        private ServletInputStream stream;

        Bounded(HttpServletRequest request, long limit) {
            super(request);
            this.limit = limit;
        }

        @Override
        public synchronized ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                ServletInputStream in = super.getInputStream();
                stream = new ServletInputStream() {
                    private long read;

                    @Override
                    public int read() throws IOException {
                        int b = in.read();
                        if (b >= 0) {
                            count(1);
                        }
                        return b;
                    }

                    @Override
                    public int read(byte[] buffer, int offset, int length) throws IOException {
                        int n = in.read(buffer, offset, (int) Math.min(length, limit - read + 1));
                        if (n > 0) {
                            count(n);
                        }
                        return n;
                    }

                    private void count(int n) throws BodyTooLargeException {
                        read += n;
                        if (read > limit) {
                            throw new BodyTooLargeException();
                        }
                    }

                    @Override
                    public boolean isFinished() {
                        return in.isFinished();
                    }

                    @Override
                    public boolean isReady() {
                        return in.isReady();
                    }

                    @Override
                    public void setReadListener(ReadListener listener) {
                        in.setReadListener(listener);
                    }
                };
            }
            return stream;
        }

        @Override
        public java.io.BufferedReader getReader() {
            throw new IllegalStateException("bodies are read as streams");
        }
    }
}
