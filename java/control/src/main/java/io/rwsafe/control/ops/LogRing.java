package io.rwsafe.control.ops;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.AppenderBase;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * The control plane's own log as classes and counts (Administration -> Platform -> System logs, PO decision Q-47
 * decision 1.4; AGENTS.md 4.14): a small bounded appender on the root logger that keeps, per instance and in memory,
 * <ul>
 *   <li>a count per level and logger (the class's short name) in hourly buckets over the last {@value #HOURS} hours, at
 *       most {@value #MAX_KEYS} level-and-logger pairs (more are counted under {@value #OTHER});</li>
 *   <li>the last {@value #RECENT} WARN and ERROR events reduced to time, level, logger, the exception's class name and
 *       the message <em>template</em> of this product's own code (the format string before its arguments are filled
 *       in), and only when that template has the shape of fixed text ({@link #fixedTemplate}).</li>
 * </ul>
 * A formatted message, an argument, an exception's message, a stack trace, an MDC value or a third-party logger's
 * template never enters it, so no identifier and no request or response body can. Readers apply the identifier and
 * estate checks to each kept template once more before showing it.
 */
@Component
public class LogRing implements DisposableBean {

    public static final int HOURS = 24;
    public static final int MAX_KEYS = 256;
    public static final int RECENT = 50;
    public static final int MAX_TEMPLATE = 160;
    /** A template with a longer run of digits is not fixed text (a number, an account, an identifier). */
    static final int MAX_DIGITS = 4;
    public static final String OTHER = "other";
    private static final String OWN_PREFIX = "io.rwsafe.";
    private static final long HOUR_MILLIS = 3_600_000L;

    /** One level-and-logger count over the window. */
    public record Count(String level, String logger, boolean own, long count) {
    }

    /** One WARN or ERROR event; {@code template} null when it was not kept (third-party or not fixed text). */
    public record Event(Instant at, String level, String logger, boolean own, String exceptionClass, String template) {
    }

    private record Key(String level, String logger, boolean own) {
    }

    private static final class Buckets {
        private final long[] counts = new long[HOURS];
        private final long[] hours = new long[HOURS];

        synchronized void add(long hour) {
            int i = (int) Math.floorMod(hour, (long) HOURS);
            if (hours[i] != hour) {
                hours[i] = hour;
                counts[i] = 0;
            }
            counts[i]++;
        }

        synchronized long sum(long nowHour) {
            long total = 0;
            for (int i = 0; i < HOURS; i++) {
                if (hours[i] > nowHour - HOURS && hours[i] <= nowHour) {
                    total += counts[i];
                }
            }
            return total;
        }
    }

    private final Clock clock;
    private final Instant since;
    private final Map<Key, Buckets> counts = new ConcurrentHashMap<>();
    private final Deque<Event> recent = new ArrayDeque<>(RECENT);
    private final RingAppender appender;
    private volatile boolean capturing;

    @Autowired
    public LogRing() {
        this(Clock.systemUTC(), true);
    }

    /** Without {@code attach}, events arrive through {@link #accept} only (tests). */
    LogRing(Clock clock, boolean attach) {
        this.clock = clock;
        this.since = clock.instant();
        this.appender = new RingAppender(this);
        if (attach) {
            attach();
        }
    }

    private void attach() {
        ILoggerFactory factory = LoggerFactory.getILoggerFactory();
        if (factory instanceof LoggerContext context) {
            appender.setContext(context);
            appender.setName("rwsafe-log-ring");
            appender.start();
            context.getLogger(Logger.ROOT_LOGGER_NAME).addAppender(appender);
            capturing = true;
        }
    }

    @Override
    public void destroy() {
        if (capturing && appender.getContext() instanceof LoggerContext context) {
            context.getLogger(Logger.ROOT_LOGGER_NAME).detachAppender(appender);
            appender.stop();
            capturing = false;
        }
    }

    /** True while the appender is attached (logback is the logging backend). */
    public boolean capturing() {
        return capturing;
    }

    public Instant since() {
        return since;
    }

    /** The logback side: reads level, logger name, the raw template and the throwable's class name; nothing else. */
    static final class RingAppender extends AppenderBase<ILoggingEvent> {

        private final LogRing ring;

        RingAppender(LogRing ring) {
            this.ring = ring;
        }

        @Override
        protected void append(ILoggingEvent e) {
            IThrowableProxy t = e.getThrowableProxy();
            ring.accept(e.getLevel().toString(), e.getLoggerName(), e.getMessage(), t == null ? null : t.getClassName(),
                Instant.ofEpochMilli(e.getTimeStamp()));
        }
    }

    /**
     * Records one event. {@code template} is the unformatted message pattern; {@code throwableClass} a class name.
     * Must never throw: it runs inside every log call.
     */
    void accept(String level, String loggerName, String template, String throwableClass, Instant at) {
        try {
            String lvl = level(level);
            boolean own = loggerName != null && loggerName.startsWith(OWN_PREFIX);
            String logger = shortName(loggerName);
            Key key = new Key(lvl, logger, own);
            Buckets b = counts.get(key);
            if (b == null) {
                b = counts.size() < MAX_KEYS ? counts.computeIfAbsent(key, k -> new Buckets())
                    : counts.computeIfAbsent(new Key(lvl, OTHER, false), k -> new Buckets());
            }
            b.add(Math.floorDiv(at.toEpochMilli(), HOUR_MILLIS));
            if (lvl.equals("WARN") || lvl.equals("ERROR")) {
                Event event = new Event(at, lvl, logger, own, throwableClass == null ? null : shortName(throwableClass),
                    own ? fixedTemplate(template) : null);
                synchronized (recent) {
                    if (recent.size() == RECENT) {
                        recent.removeFirst();
                    }
                    recent.addLast(event);
                }
            }
        } catch (RuntimeException ignored) {
            // A log call must never fail because of this appender.
        }
    }

    /** Counts per level and logger over the last {@value #HOURS} hours, most frequent first. */
    public List<Count> counts() {
        long nowHour = Math.floorDiv(clock.instant().toEpochMilli(), HOUR_MILLIS);
        List<Count> out = new ArrayList<>();
        counts.forEach((k, b) -> {
            long n = b.sum(nowHour);
            if (n > 0) {
                out.add(new Count(k.level(), k.logger(), k.own(), n));
            }
        });
        out.sort(Comparator.comparingLong(Count::count).reversed().thenComparing(Count::level)
            .thenComparing(Count::logger));
        return out;
    }

    /** The last WARN and ERROR events, newest first. */
    public List<Event> recent() {
        synchronized (recent) {
            List<Event> out = new ArrayList<>(recent);
            java.util.Collections.reverse(out);
            return out;
        }
    }

    static String level(String level) {
        return switch (level == null ? "" : level) {
            case "TRACE", "DEBUG", "INFO", "WARN", "ERROR" -> level;
            default -> OTHER;
        };
    }

    /** The last segment of a class or logger name, when it is a plain Java identifier; otherwise {@value #OTHER}. */
    static String shortName(String name) {
        if (name == null || name.isEmpty()) {
            return OTHER;
        }
        String s = name.substring(name.lastIndexOf('.') + 1);
        if (s.isEmpty() || s.length() > 64 || !Character.isJavaIdentifierStart(s.charAt(0))) {
            return OTHER;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$')) {
                return OTHER;
            }
        }
        return s;
    }

    /**
     * The template when it has the shape of fixed text, else null: at most {@value #MAX_TEMPLATE} characters of ASCII
     * letters, digits, spaces, {@code {}} placeholders and {@code , ; : ( ) ' % - _ ? !}, with a dot only where a
     * sentence ends (followed by a space or the end), and no run of more than {@value #MAX_DIGITS} digits. No {@code @},
     * {@code /}, {@code \}, {@code =} or a dot inside a word, so no e-mail address, host name, address, path, key-value
     * pair or long number fits.
     */
    static String fixedTemplate(String t) {
        if (t == null || t.isBlank() || t.length() > MAX_TEMPLATE) {
            return null;
        }
        int digits = 0;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' '
                || "{},;:()'%-_?!".indexOf(c) >= 0
                || (c == '.' && (i == t.length() - 1 || t.charAt(i + 1) == ' '));
            digits = c >= '0' && c <= '9' ? digits + 1 : 0;
            if (!ok || digits > MAX_DIGITS) {
                return null;
            }
        }
        return t;
    }
}
