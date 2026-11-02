package io.rwsafe.control.ops;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.ApiInventory;
import io.rwsafe.control.support.Synthetic;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The System logs appender (AGENTS.md 4.14, PO decision Q-47 decision 1.4): counts per level and logger, and the last
 * WARN/ERROR events as logger, exception class and a fixed template only. No argument, formatted message, exception
 * message or third-party template passes, so no identifier and no body can.
 */
class LogRingTest {

    private static final Instant NOW = Instant.parse("2026-11-02T09:30:00Z");

    /** Synthetic values of every class the product must never show, built at runtime (AGENTS.md 4.5). */
    private static List<String> canaries() {
        String email = "synthetic.person" + "@" + "example.test";
        String address = "192.0.2." + "77";
        String host = "synthetic-host-17." + "example.test";
        String prompt = "Please summarise the customer letter of Ayse Yilmaz";
        return List.of(Synthetic.tckn(41), Synthetic.iban(42), email, address, host, prompt, "Yilmaz");
    }

    private static void assertNoCanary(Object shown) {
        String s = String.valueOf(shown);
        for (String c : canaries()) {
            assertFalse(s.contains(c), "a value reached the log view: class of " + canaries().indexOf(c));
        }
    }

    @Test
    void realLogCallsLeaveOnlyLevelsLoggersExceptionClassesAndFixedTemplates() {
        LogRing ring = new LogRing(Clock.fixed(NOW, ZoneOffset.UTC), true);
        try {
            assertTrue(ring.capturing(), "logback is the backend in tests");
            List<String> c = canaries();
            Logger own = LoggerFactory.getLogger("io.rwsafe.control.synthetic.SyntheticJob");
            Logger vendor = LoggerFactory.getLogger("org.synthetic.vendor.VendorClient");
            own.warn("synthetic job failed for {} at {}", c.get(2), c.get(3));
            own.error("synthetic read failed: {}", c.get(5), new IllegalStateException("for " + c.get(0) + " " + c.get(1)));
            own.warn("concatenated value " + c.get(2));
            own.warn("concatenated host " + c.get(4) + ".");
            own.warn("concatenated number " + c.get(0));
            vendor.warn("vendor fixed text without values");
            vendor.error("vendor says {}", c.get(5), new RuntimeException(c.get(4)));
            own.info("synthetic info line {}", c.get(0));

            List<LogRing.Event> recent = ring.recent();
            assertEquals(7, recent.size());
            assertNoCanary(recent);
            assertNoCanary(ring.counts());

            LogRing.Event vendorError = recent.get(0);
            assertEquals("VendorClient", vendorError.logger());
            assertFalse(vendorError.own());
            assertEquals("RuntimeException", vendorError.exceptionClass());
            assertNull(vendorError.template(), "a third-party template is never kept");
            assertNull(recent.get(1).template(), "not even a fixed one");

            LogRing.Event ownError = recent.get(5);
            assertEquals("ERROR", ownError.level());
            assertEquals("SyntheticJob", ownError.logger());
            assertEquals("IllegalStateException", ownError.exceptionClass());
            assertEquals("synthetic read failed: {}", ownError.template());
            assertEquals("synthetic job failed for {} at {}", recent.get(6).template());
            // A concatenated e-mail address, host name or long number does not have the shape of fixed text. (A
            // concatenated name would; everyOwnLogCallsTemplateIsALiteral proves no own call concatenates a value, and
            // the reader checks each template for identifiers and estate terms once more.)
            assertNull(recent.get(4).template());
            assertNull(recent.get(3).template());
            assertNull(recent.get(2).template());

            long ownWarn = ring.counts().stream().filter(x -> x.logger().equals("SyntheticJob")
                && x.level().equals("WARN")).mapToLong(LogRing.Count::count).sum();
            assertEquals(4, ownWarn);
            assertTrue(ring.counts().stream().anyMatch(x -> x.level().equals("INFO") && x.own()));
        } finally {
            ring.destroy();
        }
        assertFalse(ring.capturing());
    }

    @Test
    void theRingIsBounded() {
        LogRing ring = new LogRing(Clock.fixed(NOW, ZoneOffset.UTC), false);
        for (int i = 0; i < LogRing.MAX_KEYS + 40; i++) {
            ring.accept("WARN", "io.rwsafe.synthetic.Logger" + i, "fixed text", null, NOW);
        }
        assertEquals(LogRing.RECENT, ring.recent().size());
        assertEquals(LogRing.MAX_KEYS + 1, ring.counts().size(), "the keys beyond the cap share one 'other' count");
        assertEquals(40, ring.counts().stream().filter(c -> c.logger().equals(LogRing.OTHER))
            .mapToLong(LogRing.Count::count).sum());
    }

    @Test
    void countsLeaveTheWindowAfterADay() {
        Instant later = NOW.plusSeconds(25 * 3600);
        LogRing ring = new LogRing(Clock.fixed(later, ZoneOffset.UTC), false);
        ring.accept("ERROR", "io.rwsafe.synthetic.Old", "old", null, NOW);
        ring.accept("ERROR", "io.rwsafe.synthetic.New", "new", null, later.minusSeconds(60));
        assertEquals(List.of("New"), ring.counts().stream().map(LogRing.Count::logger).toList());
    }

    @Test
    void onlyFixedTextIsATemplate() {
        assertEquals("capture maintenance failed: {}", LogRing.fixedTemplate("capture maintenance failed: {}"));
        assertEquals("Done. Next one.", LogRing.fixedTemplate("Done. Next one."));
        assertEquals("no reading for 5 minutes", LogRing.fixedTemplate("no reading for 5 minutes"));
        for (String bad : List.of("to " + "a" + "@" + "b", "path /var/lib/x", "host synthetic.example", "k=v",
            "back\\slash", "x".repeat(LogRing.MAX_TEMPLATE + 1), "", "  ", "tab\there", "Türkçe", "n 1234567")) {
            assertNull(LogRing.fixedTemplate(bad), bad.length() > 40 ? "long" : bad);
        }
        assertEquals(LogRing.OTHER, LogRing.shortName("io.rwsafe.bad name"));
        assertEquals(LogRing.OTHER, LogRing.shortName(null));
        assertEquals("Inner$Class", LogRing.shortName("io.rwsafe.Outer.Inner$Class"));
        assertEquals(LogRing.OTHER, LogRing.level("FATAL"));
    }

    /**
     * The templates the ring keeps are this product's own format strings; this proves every log call of the modules on
     * the control plane's classpath starts with string literals only (concatenated literals allowed), so a value can
     * only ever be an argument, which the ring never reads.
     */
    @Test
    void everyOwnLogCallsTemplateIsALiteral() throws IOException {
        Pattern call = Pattern.compile("\\b(LOG|LOGGER|log)\\s*\\.\\s*(trace|debug|info|warn|error)\\s*\\(");
        List<String> violations = new ArrayList<>();
        int calls = 0;
        Path java = ApiInventory.repositoryRoot().resolve("java");
        for (String module : List.of("control", "persistence", "platform-core", "detect", "policy")) {
            Path src = java.resolve(module).resolve("src/main/java");
            if (!Files.isDirectory(src)) {
                continue;
            }
            try (Stream<Path> files = Files.walk(src)) {
                for (Path f : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                    String text = Files.readString(f);
                    Matcher m = call.matcher(text);
                    while (m.find()) {
                        calls++;
                        if (!literalTemplate(text, m.end())) {
                            int line = (int) text.substring(0, m.start()).chars().filter(ch -> ch == '\n').count() + 1;
                            violations.add(java.relativize(f) + ":" + line);
                        }
                    }
                }
            }
        }
        assertTrue(calls > 20, "the scan found " + calls + " log calls");
        assertTrue(violations.isEmpty(), "log calls whose template is not a literal: " + violations);
    }

    /** From just after {@code (}: string literals joined by {@code +}, then {@code ,} or {@code )}. */
    private static boolean literalTemplate(String s, int i) {
        while (true) {
            i = skipSpace(s, i);
            if (i >= s.length() || s.charAt(i) != '"') {
                return false;
            }
            i++;
            while (i < s.length() && s.charAt(i) != '"') {
                i += s.charAt(i) == '\\' ? 2 : 1;
            }
            i = skipSpace(s, i + 1);
            if (i >= s.length()) {
                return false;
            }
            char c = s.charAt(i);
            if (c == ',' || c == ')') {
                return true;
            }
            if (c != '+') {
                return false;
            }
            i++;
        }
    }

    private static int skipSpace(String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        return i;
    }
}
