package io.rwsafe.control.sample;

import io.rwsafe.control.ingest.VerdictEventPayload;
import io.rwsafe.control.ingest.VerdictEventPayload.FindingPayload;
import java.time.DayOfWeek;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;

/**
 * Synthetic verdict events shaped like the data plane's (ADR-009 C11: synthetic only, never captured content), so the
 * admin UI is demonstrable before real traffic: the platform-matrix platforms with their surfaces, a business-hours
 * curve in Europe/Istanbul over the last seven days, a realistic verdict mix and the Tier-1 finding classes. Users are
 * synthetic claims that ingestion pseudonymises like any other; addresses come from the RFC 5737 documentation ranges.
 * Deterministic for one seed.
 */
public final class SampleEvents {

    private static final ZoneId ISTANBUL = ZoneId.of("Europe/Istanbul");
    private static final String[] DOC_NETS = {"192.0.2.", "198.51.100.", "203.0.113."};

    private record Platform(String id, int weight, String[] surfaces, String step) {
    }

    private static final Platform[] PLATFORMS = {
        new Platform("openai", 25, new String[] {"web", "web", "api", "cli"}, null),
        new Platform("copilot", 22, new String[] {"ide", "ide", "ide", "web"}, null),
        new Platform("claude", 18, new String[] {"web", "api", "cli", "ide"}, null),
        new Platform("gemini", 12, new String[] {"web", "api", "ide"}, null),
        new Platform("github", 6, new String[] {"web", "api"}, null),
        new Platform("windsurf", 4, new String[] {"ide"}, null),
        new Platform("devin", 3, new String[] {"web", "api"}, null),
        new Platform("microsoft-auth", 5, new String[] {"web"}, "login"),
        new Platform("google-auth", 3, new String[] {"web"}, "login"),
        new Platform("unknown", 2, new String[] {"unknown"}, "other"),
    };
    private static final int TOTAL_WEIGHT = java.util.Arrays.stream(PLATFORMS).mapToInt(Platform::weight).sum();
    /** The data plane's reason classes for UNINSPECTABLE (ICAP engine slice 1). */
    private static final String[] NON_VERDICT_REASONS = {"BINARY", "MULTIPART", "UNSUPPORTED_MEDIA", "ENCODED", "OVERSIZE",
        "UNSUPPORTED_CHARSET"};

    private final Random random;
    private final int users;

    public SampleEvents(long seed, int users) {
        this.random = new Random(seed);
        this.users = users;
    }

    /** {@code count} events ending at {@code now}, oldest first. */
    public List<VerdictEventPayload> generate(int count, Instant now) {
        List<VerdictEventPayload> out = new ArrayList<>(count);
        Instant start = now.minus(Duration.ofDays(7)).truncatedTo(ChronoUnit.HOURS);
        while (out.size() < count) {
            Instant at = start.plusSeconds((long) (random.nextDouble() * Duration.between(start, now).toSeconds()));
            if (random.nextDouble() > activity(at)) {
                continue;
            }
            out.add(event(at));
        }
        out.sort(java.util.Comparator.comparing(VerdictEventPayload::receivedAt));
        return out;
    }

    /** Relative activity: working hours on weekdays, a little in the evening, almost none at night or at weekends. */
    private static double activity(Instant at) {
        ZonedDateTime local = at.atZone(ISTANBUL);
        int h = local.getHour();
        double hour = h >= 9 && h < 18 ? (h == 12 ? 0.6 : 1.0) : h >= 7 && h < 21 ? 0.25 : 0.03;
        boolean weekend = local.getDayOfWeek() == DayOfWeek.SATURDAY || local.getDayOfWeek() == DayOfWeek.SUNDAY;
        return weekend ? hour * 0.12 : hour;
    }

    private VerdictEventPayload event(Instant at) {
        Platform p = platform();
        String surface = p.surfaces()[random.nextInt(p.surfaces().length)];
        String step = p.step() != null ? p.step() : chatStep();
        boolean respmod = p.step() == null && random.nextDouble() < 0.2;
        int user = (int) Math.floor(Math.pow(random.nextDouble(), 1.6) * users);
        String verdict;
        String reason = null;
        List<FindingPayload> findings = new ArrayList<>();
        double r = random.nextDouble();
        if (p.id().equals("unknown")) {
            verdict = "UNKNOWN_FLOW";
        } else if ("login".equals(p.step())) {
            // Sign-in steps: tenant restriction refuses a personal account (ADR-007, ADR-009 PC-9), never a DLP class.
            verdict = r < 0.9 ? "ALLOW" : r < 0.98 ? "BLOCK" : "UNINSPECTABLE";
            reason = verdict.equals("ALLOW") ? null : verdict.equals("BLOCK") ? "NON_CORPORATE_ACCOUNT" : "ENCODED";
        } else if (respmod) {
            verdict = r < 0.96 ? "ALLOW" : r < 0.985 ? "REDACT" : "STREAM_ABORTED";
            if (!verdict.equals("ALLOW")) {
                reason = verdict.equals("REDACT") ? "customer_data" : "secret";
                findings.add(new FindingPayload(verdict.equals("REDACT") ? "TCKN" : "SECRET", 1));
            }
        } else if (r < 0.78) {
            verdict = "ALLOW";
        } else if (r < 0.80) {
            verdict = "WARN";
        } else if (r < 0.89) {
            verdict = "REDACT";
            reason = "customer_data";
            String[] classes = {"TCKN", "TCKN", "TR_IBAN", "PAYMENT_CARD"};
            findings.add(new FindingPayload(classes[random.nextInt(classes.length)], 1 + random.nextInt(3)));
            if (random.nextDouble() < 0.15) {
                findings.add(new FindingPayload("TR_IBAN".equals(findings.get(0).dataClass()) ? "TCKN" : "TR_IBAN", 1));
            }
        } else if (r < 0.95) {
            verdict = "BLOCK";
            reason = "secret";
            findings.add(new FindingPayload("SECRET", 1 + random.nextInt(2)));
        } else if (r < 0.98) {
            verdict = "UNINSPECTABLE";
            reason = NON_VERDICT_REASONS[random.nextInt(NON_VERDICT_REASONS.length)];
        } else if (r < 0.99) {
            verdict = "MALFORMED";
            reason = random.nextBoolean() ? "HTTP_HEAD" : "JSON";
        } else if (r < 0.996) {
            verdict = "INSPECTION_TIMEOUT";
            reason = "BODY_RECEIVE";
        } else {
            verdict = "INSPECTION_FAILED";
            reason = "INTERNAL";
        }
        String id = new UUID(random.nextLong(), random.nextLong()).toString();
        long bodyBytes = p.step() != null ? 300 + random.nextInt(1500)
            : (long) Math.min(4L * 1024 * 1024, Math.exp(6 + random.nextGaussian() * 1.4 + 2));
        long micros = (long) Math.max(40, Math.exp(5.5 + random.nextGaussian() * 0.7) + bodyBytes / 60.0);
        String address = DOC_NETS[user % DOC_NETS.length] + (10 + user % 200);
        return new VerdictEventPayload(id, at.toString(), respmod ? "respmod" : "reqmod", p.id(), surface, step,
            verdict, reason, findings, bodyBytes, micros, "synthetic.user." + String.format("%03d", user), address,
            "plain_allowlisted", 1L, id, null, null);
    }

    private Platform platform() {
        int pick = random.nextInt(TOTAL_WEIGHT);
        for (Platform p : PLATFORMS) {
            pick -= p.weight();
            if (pick < 0) {
                return p;
            }
        }
        return PLATFORMS[0];
    }

    private String chatStep() {
        double r = random.nextDouble();
        return r < 0.82 ? "chat" : r < 0.94 ? "tool_call" : "upload";
    }
}
