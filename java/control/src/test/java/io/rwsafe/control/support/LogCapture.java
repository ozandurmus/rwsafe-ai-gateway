package io.rwsafe.control.support;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.AppenderBase;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import org.slf4j.LoggerFactory;

/**
 * Everything the JVM logs while installed (AGENTS.md 4.14, SR-PRIV-6): every Logback event (the control plane, Spring,
 * Tomcat, Netty through SLF4J) with its formatted message, MDC, key-value pairs and the whole throwable (messages of
 * every cause and suppressed exception, and the stack); every {@code java.util.logging} record that does not reach
 * Logback; and every uncaught exception. The rwsafe loggers run at TRACE and Netty's at DEBUG while installed, so the
 * product's own statements are scanned at every level; third-party loggers keep the production levels.
 */
public final class LogCapture implements AutoCloseable {

    private final StringBuffer logback = new StringBuffer();
    private final StringBuffer jul = new StringBuffer();
    private final StringBuffer uncaught = new StringBuffer();
    private final LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
    private final AppenderBase<ILoggingEvent> appender;
    private final Handler handler;
    private final Thread.UncaughtExceptionHandler previousUncaught = Thread.getDefaultUncaughtExceptionHandler();
    private final Map<String, Level> previousLevels = new HashMap<>();
    private int events;

    public LogCapture() {
        appender = new AppenderBase<>() {
            @Override
            protected void append(ILoggingEvent e) {
                events++;
                logback.append(e.getLevel()).append(' ').append(e.getLoggerName()).append(' ')
                    .append(e.getFormattedMessage()).append(' ').append(e.getMDCPropertyMap());
                // Arguments without a placeholder never reach the formatted message; they are scanned too (D-05).
                if (e.getArgumentArray() != null) {
                    logback.append(' ').append(java.util.Arrays.deepToString(e.getArgumentArray()));
                }
                if (e.getKeyValuePairs() != null) {
                    logback.append(' ').append(e.getKeyValuePairs());
                }
                IThrowableProxy t = e.getThrowableProxy();
                if (t != null) {
                    logback.append('\n').append(ThrowableProxyUtil.asString(t));
                }
                logback.append('\n');
            }
        };
        appender.setContext(context);
        appender.setName("rwsafe-log-scanner");
        appender.start();
        context.getLogger(Logger.ROOT_LOGGER_NAME).addAppender(appender);
        level("io.rwsafe", Level.TRACE);
        level("io.netty", Level.DEBUG);

        handler = new Handler() {
            @Override
            public void publish(LogRecord r) {
                jul.append(r.getLevel()).append(' ').append(r.getLoggerName()).append(' ').append(r.getMessage());
                if (r.getParameters() != null) {
                    for (Object p : r.getParameters()) {
                        jul.append(' ').append(p);
                    }
                }
                throwable(jul, r.getThrown());
                jul.append('\n');
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        java.util.logging.Logger.getLogger("").addHandler(handler);
        Thread.setDefaultUncaughtExceptionHandler((thread, e) -> throwable(uncaught, e));
    }

    private void level(String logger, Level level) {
        Logger l = context.getLogger(logger);
        previousLevels.put(logger, l.getLevel());
        l.setLevel(level);
    }

    private static void throwable(StringBuffer into, Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            into.append('\n').append(c.getClass().getName()).append(": ").append(c.getMessage());
            for (Throwable s : c.getSuppressed()) {
                throwable(into, s);
            }
        }
    }

    /** The number of Logback events seen (a capture that saw nothing proves nothing). */
    public int events() {
        return events;
    }

    public String logback() {
        return logback.toString();
    }

    public String jul() {
        return jul.toString();
    }

    public String uncaught() {
        return uncaught.toString();
    }

    @Override
    public void close() {
        context.getLogger(Logger.ROOT_LOGGER_NAME).detachAppender(appender);
        appender.stop();
        previousLevels.forEach((name, level) -> context.getLogger(name).setLevel(level));
        java.util.logging.Logger.getLogger("").removeHandler(handler);
        Thread.setDefaultUncaughtExceptionHandler(previousUncaught);
    }
}
