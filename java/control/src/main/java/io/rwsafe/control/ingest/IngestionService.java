package io.rwsafe.control.ingest;

import io.rwsafe.control.policy.PolicyRegistryService;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.persistence.Database;
import io.rwsafe.persistence.FindingCount;
import io.rwsafe.persistence.StoredVerdictEvent;
import io.rwsafe.platform.verdict.ReasonCodes;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.policy.Flow;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Validates a batch against the ingestion contract, pseudonymises the identity claim and masks the client address with
 * rwsafe's own key, then stores metadata only (ADR-009 C1/C2/C6). The whole batch is refused when one element is invalid
 * (the data plane's batches are all-or-nothing) and when the key is missing: nothing raw is ever stored.
 */
@Service
public class IngestionService {

    public static final int MAX_BATCH = 1000;
    static final Duration MAX_AGE = Duration.ofDays(30);
    static final Duration MAX_SKEW = Duration.ofMinutes(5);
    private static final Set<String> TRANSPORTS = Set.of("plain_allowlisted", "mtls_verified");
    /** The flow classifier's fixed enumerations (ICAP spec §4.3): nothing else is a surface or a step. */
    static final Set<String> SURFACES = Set.copyOf(Arrays.stream(Flow.Surface.values())
        .map(v -> v.name().toLowerCase(Locale.ROOT)).toList());
    static final Set<String> STEPS = Set.copyOf(Arrays.stream(Flow.Step.values())
        .map(v -> v.name().toLowerCase(Locale.ROOT)).toList());

    private final Database database;
    private final PrivacyKeys keys;
    private final Pseudonymiser pseudonymiser;
    /** The registry's platform ids, read once per batch. */
    private final Supplier<Set<String>> platformIds;
    private final Clock clock;

    @Autowired
    public IngestionService(Database database, PrivacyKeys keys, Pseudonymiser pseudonymiser,
                            PolicyRegistryService registry) {
        this(database, keys, pseudonymiser, registry::platformIds, Clock.systemUTC());
    }

    /** @param platformIds the platform ids an event may name (the registry's, in the application) */
    public IngestionService(Database database, PrivacyKeys keys, Pseudonymiser pseudonymiser,
                            Supplier<Set<String>> platformIds, Clock clock) {
        this.database = database;
        this.keys = keys;
        this.pseudonymiser = pseudonymiser;
        this.platformIds = platformIds;
        this.clock = clock;
    }

    public record Result(int accepted, int duplicates) {
    }

    public Result ingest(List<VerdictEventPayload> batch) {
        if (batch == null) {
            throw new InvalidEventException("the body must be a JSON array of events");
        }
        if (batch.size() > MAX_BATCH) {
            throw new InvalidEventException("a batch holds at most " + MAX_BATCH + " events");
        }
        String keyId = keys.keyId();
        Set<String> platforms = platformIds.get();
        Instant now = clock.instant();
        List<StoredVerdictEvent> rows = new ArrayList<>(batch.size());
        Set<UUID> ids = new HashSet<>();
        for (int i = 0; i < batch.size(); i++) {
            StoredVerdictEvent row = validate(i, batch.get(i), now, keyId, platforms);
            if (ids.add(row.eventId())) {
                rows.add(row);
            }
        }
        int inserted = database.verdictEvents().insert(rows);
        return new Result(inserted, batch.size() - inserted);
    }

    private StoredVerdictEvent validate(int i, VerdictEventPayload e, Instant now, String keyId, Set<String> platforms) {
        if (e == null) {
            throw new InvalidEventException(i, "event");
        }
        UUID eventId = uuid(i, e.eventId());
        Instant receivedAt = instant(i, e.receivedAt());
        if (receivedAt.isBefore(now.minus(MAX_AGE)) || receivedAt.isAfter(now.plus(MAX_SKEW))) {
            throw new InvalidEventException(i, "receivedAt");
        }
        String service = require(i, "service", e.service());
        if (!service.equals("reqmod") && !service.equals("respmod")) {
            throw new InvalidEventException(i, "service");
        }
        // Registry vocabulary only (SR-PRIV-4): a value outside it could carry an identifier into every screen.
        String platform = member(i, "platform", e.platform(), platforms);
        String surface = member(i, "surface", e.surface(), SURFACES);
        String step = member(i, "step", e.step(), STEPS);
        Verdict verdict;
        try {
            verdict = Verdict.valueOf(require(i, "verdict", e.verdict()));
        } catch (IllegalArgumentException ex) {
            throw new InvalidEventException(i, "verdict");
        }
        // A closed vocabulary (PR 24 review D-01): the data plane's reason codes, nothing free.
        String reason = e.reason();
        if (reason != null && !ReasonCodes.known(reason)) {
            throw new InvalidEventException(i, "reason");
        }
        List<FindingCount> findings = findings(i, e.findings());
        long bodyBytes = nonNegative(i, "bodyBytes", e.bodyBytes());
        long decisionMicros = nonNegative(i, "decisionMicros", e.decisionMicros());
        if (e.userClaim() != null && e.userClaim().length() > 256) {
            throw new InvalidEventException(i, "userClaim");
        }
        if (e.clientAddress() != null && e.clientAddress().length() > 64) {
            throw new InvalidEventException(i, "clientAddress");
        }
        String transport = require(i, "transport", e.transport());
        if (!TRANSPORTS.contains(transport)) {
            throw new InvalidEventException(i, "transport");
        }
        long snapshotVersion = nonNegative(i, "snapshotVersion", e.snapshotVersion());
        String correlationId = require(i, "correlationId", e.correlationId());
        // A closed format (PR 24 review D-01): the data plane's correlation id is a random canonical UUID. Any other
        // token could carry a name, which no identifier check recognises, so nothing else is taken.
        if (!canonicalUuid(correlationId)) {
            throw new InvalidEventException(i, "correlationId");
        }
        List<String> applied = ruleIds(i, "appliedRuleIds", e.appliedRuleIds());
        List<String> monitor = ruleIds(i, "monitorRuleIds", e.monitorRuleIds());
        return new StoredVerdictEvent(eventId, receivedAt, service, platform, surface, step, verdict, reason, findings,
            bodyBytes, decisionMicros, pseudonymiser.user(e.userClaim()), pseudonymiser.subnet(e.clientAddress()),
            transport, snapshotVersion, correlationId, keyId, applied, monitor);
    }

    static final int MAX_RULE_IDS = 16;
    static final int MAX_RULE_ID_LENGTH = 128;
    private static final com.google.re2j.Pattern RULE_ID =
        com.google.re2j.Pattern.compile("class\\.([A-Z][A-Z0-9_]{1,31})@[1-9][0-9]{0,9}");

    /**
     * The optional scoped-rule ids of snapshot format 2: absent is empty; at most 16, each a DLP class rule and version
     * ({@code class.<CLASS>@<version>}, a class the platform knows, at most 128 characters), none twice (PR 21 review
     * D-04: a scoped rule is always a class rule, so no free suffix exists for a value to ride in); anything else refuses
     * the batch. The database checks the same.
     */
    private static List<String> ruleIds(int i, String field, List<String> ids) {
        if (ids == null) {
            return List.of();
        }
        if (ids.size() > MAX_RULE_IDS) {
            throw new InvalidEventException(i, field);
        }
        Set<String> seen = new HashSet<>();
        for (String id : ids) {
            if (id == null || id.length() > MAX_RULE_ID_LENGTH || !seen.add(id)) {
                throw new InvalidEventException(i, field);
            }
            com.google.re2j.Matcher m = RULE_ID.matcher(id);
            if (!m.matches() || !knownDataClass(m.group(1))) {
                throw new InvalidEventException(i, field);
            }
        }
        return ids;
    }

    private static boolean knownDataClass(String name) {
        for (io.rwsafe.platform.verdict.DataClass c : io.rwsafe.platform.verdict.DataClass.values()) {
            if (c.name().equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static List<FindingCount> findings(int i, List<VerdictEventPayload.FindingPayload> findings) {
        if (findings == null || findings.size() > 32) {
            throw new InvalidEventException(i, "findings");
        }
        List<FindingCount> out = new ArrayList<>(findings.size());
        Set<String> classes = new HashSet<>();
        for (VerdictEventPayload.FindingPayload f : findings) {
            // A known DLP class only (PR 24 confirmation review N-01): a free class name could carry an identifier.
            if (f == null || f.dataClass() == null || !knownDataClass(f.dataClass()) || !classes.add(f.dataClass())
                || f.count() == null || f.count() < 1 || f.count() > 1_000_000) {
                throw new InvalidEventException(i, "findings");
            }
            out.add(new FindingCount(f.dataClass(), f.count()));
        }
        return out;
    }

    private static String require(int i, String field, String value) {
        if (value == null) {
            throw new InvalidEventException(i, field);
        }
        return value;
    }

    private static String member(int i, String field, String value, Set<String> vocabulary) {
        if (value == null || !vocabulary.contains(value)) {
            throw new InvalidEventException(i, field);
        }
        return value;
    }

    private static long nonNegative(int i, String field, Long value) {
        if (value == null || value < 0) {
            throw new InvalidEventException(i, field);
        }
        return value;
    }

    private static UUID uuid(int i, String value) {
        try {
            UUID id = UUID.fromString(require(i, "eventId", value));
            if (!id.toString().equals(value.toLowerCase(java.util.Locale.ROOT))) {
                throw new InvalidEventException(i, "eventId");
            }
            return id;
        } catch (IllegalArgumentException ex) {
            throw new InvalidEventException(i, "eventId");
        }
    }

    private static Instant instant(int i, String value) {
        try {
            return Instant.parse(require(i, "receivedAt", value));
        } catch (DateTimeParseException ex) {
            throw new InvalidEventException(i, "receivedAt");
        }
    }

    /**
     * The data plane's correlation id is a lower-case canonical UUID, the only form ingestion takes (PR 24 review D-01):
     * random hex, so its digit groups can look like a Luhn-valid card number by chance, and it can carry no value.
     */
    public static boolean canonicalUuid(String s) {
        if (s.length() != 36) {
            return false;
        }
        try {
            return UUID.fromString(s).toString().equals(s);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
