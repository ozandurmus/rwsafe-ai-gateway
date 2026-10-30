package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import io.rwsafe.platform.verdict.Verdict;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.jooq.Condition;
import org.jooq.DSLContext;
import org.jooq.Field;
import org.jooq.Record;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

/**
 * Read model for the admin screens: overview aggregates, the traffic list with keyset pagination and the event detail.
 * Filters take pseudonyms and vocabulary only; there is no filter on a raw identity or address, so the list cannot be
 * used as a "does this person exist" oracle (ADR-009 §6).
 */
public final class VerdictQueries {

    /** Largest page the traffic list returns. */
    public static final int MAX_PAGE = 200;

    private final DSLContext dsl;

    VerdictQueries(DSLContext dsl) {
        this.dsl = dsl;
    }

    public record VerdictCount(Verdict verdict, long count) {
    }

    public record PlatformCount(String platform, long total, long redacted, long blocked, long nonVerdicts) {
    }

    public record HourBucket(Instant hour, Map<Verdict, Long> byVerdict) {
    }

    public record FindingClassCount(String dataClass, long events, long hits) {
    }

    public record Overview(Instant from, Instant to, long total, List<VerdictCount> verdicts,
                           List<PlatformCount> platforms, List<HourBucket> hours, List<FindingClassCount> findings) {
    }

    /** Every field but the window is optional (null = no filter). */
    public record TrafficFilter(Instant from, Instant to, String platform, Verdict verdict, String service,
                                String userPseudonym, int limit, String cursor) {
    }

    public record TrafficPage(List<StoredVerdictEvent> items, String nextCursor) {
    }

    public record IngestStats(long eventsSince, Instant latestReceivedAt, long totalEvents) {
    }

    public Overview overview(Instant from, Instant to) {
        Condition window = RECEIVED_AT.ge(from).and(RECEIVED_AT.lt(to));
        Field<Integer> count = DSL.count();

        List<VerdictCount> verdicts = new ArrayList<>();
        long total = 0;
        for (Record r : dsl.select(VERDICT, count).from(VERDICT_EVENT).where(window).groupBy(VERDICT)
            .orderBy(count.desc(), VERDICT).fetch()) {
            verdicts.add(new VerdictCount(Verdict.valueOf(r.get(VERDICT)), r.get(count)));
            total += r.get(count);
        }

        Field<Integer> redacted = DSL.count().filterWhere(VERDICT.eq(Verdict.REDACT.name()));
        Field<Integer> blocked = DSL.count().filterWhere(VERDICT.in(Verdict.BLOCK.name(), Verdict.STREAM_ABORTED.name()));
        Field<Integer> nonVerdicts = DSL.count().filterWhere(VERDICT.in(nonVerdictNames()));
        List<PlatformCount> platforms = dsl.select(PLATFORM, count, redacted, blocked, nonVerdicts).from(VERDICT_EVENT)
            .where(window).groupBy(PLATFORM).orderBy(count.desc(), PLATFORM).fetch(r -> new PlatformCount(
                r.get(PLATFORM), r.get(count), r.get(redacted), r.get(blocked), r.get(nonVerdicts)));

        Field<Instant> hour = DSL.field("date_trunc('hour', {0}, 'UTC')", SQLDataType.INSTANT, RECEIVED_AT);
        Map<Instant, Map<Verdict, Long>> byHour = new LinkedHashMap<>();
        for (Record r : dsl.select(hour, VERDICT, count).from(VERDICT_EVENT).where(window).groupBy(hour, VERDICT)
            .orderBy(hour).fetch()) {
            byHour.computeIfAbsent(r.get(hour), h -> new LinkedHashMap<>())
                .put(Verdict.valueOf(r.get(VERDICT)), (long) r.get(count));
        }
        List<HourBucket> hours = byHour.entrySet().stream()
            .map(e -> new HourBucket(e.getKey(), Map.copyOf(e.getValue()))).toList();

        Field<Integer> events = DSL.countDistinct(FINDING_EVENT_ID);
        Field<java.math.BigDecimal> hits = DSL.sum(HIT_COUNT);
        List<FindingClassCount> findings = dsl.select(DATA_CLASS, events, hits).from(VERDICT_FINDING)
            .join(VERDICT_EVENT).on(EVENT_ID.eq(FINDING_EVENT_ID)).where(window).groupBy(DATA_CLASS)
            .orderBy(events.desc(), DATA_CLASS)
            .fetch(r -> new FindingClassCount(r.get(DATA_CLASS), r.get(events), r.get(hits).longValue()));

        return new Overview(from, to, total, verdicts, platforms, hours, findings);
    }

    public TrafficPage traffic(TrafficFilter f) {
        int limit = Math.max(1, Math.min(f.limit(), MAX_PAGE));
        Condition c = DSL.trueCondition();
        if (f.from() != null) {
            c = c.and(RECEIVED_AT.ge(f.from()));
        }
        if (f.to() != null) {
            c = c.and(RECEIVED_AT.lt(f.to()));
        }
        if (f.platform() != null) {
            c = c.and(PLATFORM.eq(f.platform()));
        }
        if (f.verdict() != null) {
            c = c.and(VERDICT.eq(f.verdict().name()));
        }
        if (f.service() != null) {
            c = c.and(SERVICE.eq(f.service()));
        }
        if (f.userPseudonym() != null) {
            c = c.and(USER_PSEUDONYM.eq(f.userPseudonym()));
        }
        if (f.cursor() != null) {
            Cursor cursor = Cursor.decode(f.cursor());
            c = c.and(DSL.row(RECEIVED_AT, EVENT_ID).lt(cursor.receivedAt(), cursor.eventId()));
        }
        List<Record> rows = dsl.select(eventFields()).from(VERDICT_EVENT).where(c)
            .orderBy(RECEIVED_AT.desc(), EVENT_ID.desc()).limit(limit + 1).fetch();
        boolean more = rows.size() > limit;
        List<Record> page = more ? rows.subList(0, limit) : rows;
        Map<UUID, List<FindingCount>> findings = findings(page.stream().map(r -> r.get(EVENT_ID)).toList());
        List<StoredVerdictEvent> items = page.stream()
            .map(r -> toEvent(r, findings.getOrDefault(r.get(EVENT_ID), List.of()))).toList();
        String next = null;
        if (more) {
            StoredVerdictEvent last = items.get(items.size() - 1);
            next = new Cursor(last.receivedAt(), last.eventId()).encode();
        }
        return new TrafficPage(items, next);
    }

    public Optional<StoredVerdictEvent> event(UUID eventId) {
        Record r = dsl.select(eventFields()).from(VERDICT_EVENT).where(EVENT_ID.eq(eventId)).fetchOne();
        if (r == null) {
            return Optional.empty();
        }
        return Optional.of(toEvent(r, findings(List.of(eventId)).getOrDefault(eventId, List.of())));
    }

    /** Distinct platform ids seen in the window, for the traffic filter. */
    public List<String> platforms(Instant from, Instant to) {
        return dsl.selectDistinct(PLATFORM).from(VERDICT_EVENT).where(RECEIVED_AT.ge(from).and(RECEIVED_AT.lt(to)))
            .orderBy(PLATFORM).fetch(PLATFORM);
    }

    /** Stored events with this verdict and exactly this (sorted) set of finding classes. */
    public record ClassCombination(Verdict verdict, List<String> classes, long events) {

        public ClassCombination {
            classes = List.copyOf(classes);
        }
    }

    public record SimulationBase(long eventsInWindow, List<ClassCombination> combinations) {

        public SimulationBase {
            combinations = List.copyOf(combinations);
        }
    }

    /**
     * Stored events in the window grouped by verdict and the set of finding classes they carry, for the policy
     * simulation: one row per (verdict, sorted class set) with its count, plus the number of events in the window. Counts
     * only; no event is returned.
     *
     * @param dataClass when set, only events with a finding of this class
     */
    public SimulationBase classCombinations(Instant from, Instant to, String dataClass) {
        Condition window = RECEIVED_AT.ge(from).and(RECEIVED_AT.lt(to));
        Field<String[]> classes = DSL.arrayAgg(DATA_CLASS).orderBy(DATA_CLASS).as("classes");
        var perEvent = dsl.select(EVENT_ID, VERDICT, classes).from(VERDICT_EVENT).join(VERDICT_FINDING)
            .on(FINDING_EVENT_ID.eq(EVENT_ID)).where(window).groupBy(EVENT_ID, VERDICT).asTable("per_event");
        Field<String> verdict = perEvent.field(VERDICT.getName(), String.class);
        Field<String[]> classSet = perEvent.field("classes", String[].class);
        Condition withClass = dataClass == null ? DSL.trueCondition()
            : DSL.condition("{0} = ANY({1})", DSL.val(dataClass), classSet);
        Field<Integer> count = DSL.count();
        List<ClassCombination> rows = dsl.select(verdict, classSet, count).from(perEvent).where(withClass)
            .groupBy(verdict, classSet).orderBy(count.desc()).fetch(r -> new ClassCombination(
                Verdict.valueOf(r.get(verdict)), List.of(r.get(classSet)), r.get(count)));
        long total = dsl.fetchCount(VERDICT_EVENT, window);
        return new SimulationBase(total, rows);
    }

    public IngestStats ingestStats(Instant since) {
        Field<Integer> recent = DSL.count().filterWhere(INGESTED_AT.ge(since));
        Field<Instant> latest = DSL.max(RECEIVED_AT);
        Field<Integer> all = DSL.count();
        Record r = dsl.select(recent, latest, all).from(VERDICT_EVENT).fetchOne();
        return new IngestStats(r.get(recent), r.get(latest), r.get(all));
    }

    static List<Field<?>> eventFields() {
        return List.of(EVENT_ID, RECEIVED_AT, SERVICE, PLATFORM, SURFACE, STEP, VERDICT, REASON, BODY_BYTES,
            DECISION_MICROS, USER_PSEUDONYM, CLIENT_SUBNET, TRANSPORT, SNAPSHOT_VERSION, CORRELATION_ID,
            PSEUDONYM_KEY_ID, APPLIED_RULE_IDS, MONITOR_RULE_IDS);
    }

    Map<UUID, List<FindingCount>> findings(List<UUID> eventIds) {
        Map<UUID, List<FindingCount>> out = new LinkedHashMap<>();
        if (eventIds.isEmpty()) {
            return out;
        }
        for (Record r : dsl.select(FINDING_EVENT_ID, DATA_CLASS, HIT_COUNT).from(VERDICT_FINDING)
            .where(FINDING_EVENT_ID.in(eventIds)).orderBy(FINDING_EVENT_ID, DATA_CLASS).fetch()) {
            out.computeIfAbsent(r.get(FINDING_EVENT_ID), id -> new ArrayList<>())
                .add(new FindingCount(r.get(DATA_CLASS), r.get(HIT_COUNT)));
        }
        return out;
    }

    static StoredVerdictEvent toEvent(Record r, List<FindingCount> findings) {
        return new StoredVerdictEvent(r.get(EVENT_ID), r.get(RECEIVED_AT), r.get(SERVICE), r.get(PLATFORM),
            r.get(SURFACE), r.get(STEP), Verdict.valueOf(r.get(VERDICT)), r.get(REASON), findings, r.get(BODY_BYTES),
            r.get(DECISION_MICROS), r.get(USER_PSEUDONYM), r.get(CLIENT_SUBNET), r.get(TRANSPORT),
            r.get(SNAPSHOT_VERSION), r.get(CORRELATION_ID), r.get(PSEUDONYM_KEY_ID),
            ids(r.get(APPLIED_RULE_IDS)), ids(r.get(MONITOR_RULE_IDS)));
    }

    /** PR 21 review D-02: the scoped-rule ids are read back as stored (an absent array reads as empty). */
    private static List<String> ids(String[] values) {
        return values == null ? List.of() : List.of(values);
    }

    private static List<String> nonVerdictNames() {
        List<String> names = new ArrayList<>();
        for (Verdict v : Verdict.values()) {
            if (v.isNonVerdict()) {
                names.add(v.name());
            }
        }
        return names;
    }

    /** Opaque keyset cursor: the last row's {@code (received_at, event_id)}. */
    record Cursor(Instant receivedAt, UUID eventId) {

        String encode() {
            String raw = receivedAt.getEpochSecond() + "." + receivedAt.getNano() + "." + eventId;
            return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.US_ASCII));
        }

        /** @throws IllegalArgumentException for anything this class did not encode */
        static Cursor decode(String token) {
            if (token.length() > 128) {
                throw new IllegalArgumentException("cursor too long");
            }
            String raw = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.US_ASCII);
            String[] parts = raw.split("\\.", 3);
            if (parts.length != 3) {
                throw new IllegalArgumentException("malformed cursor");
            }
            try {
                return new Cursor(Instant.ofEpochSecond(Long.parseLong(parts[0]), Integer.parseInt(parts[1])),
                    UUID.fromString(parts[2]));
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("malformed cursor", e);
            }
        }
    }
}
