package io.rwsafe.control.notice;

import io.rwsafe.control.api.ApiExceptionHandler.BadRequest;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.persistence.Database;
import io.rwsafe.persistence.NoticeAcknowledgement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

/**
 * The notice acknowledgement gate (ADR-009 C12, SR-PRIV-10, PC-2, PC-3): records who acknowledged which notice version,
 * when and from which source, under the user's pseudonym only, and answers whether content may be captured for a user.
 * An acknowledgement is proof of notice, never approval or consent (Q-32); the directory's HR record that the version
 * was read counts when it carries the version and the date (Q-35). A batch is all-or-nothing; a missing privacy key
 * refuses it (nothing is stored raw); an incomplete notice refuses it (nothing was shown).
 */
@Service
public class NoticeAcknowledgementService {

    public static final int MAX_BATCH = 1000;
    private static final Logger LOG = LoggerFactory.getLogger(NoticeAcknowledgementService.class);
    public static final Set<String> SOURCES =
        Set.of("banner", "ide_first_run", "directory_attribute", "gateway_credential_issue");
    /** The record of the employee's own action: they can only acknowledge the notice they are shown now (D-03). */
    static final Set<String> INTERACTIVE = Set.of("banner", "ide_first_run", "gateway_credential_issue");
    /** Clock difference tolerated between the reporting surface and the control plane, both ways. */
    static final Duration MAX_SKEW = Duration.ofMinutes(5);

    private final Database database;
    private final PrivacyKeys keys;
    private final Pseudonymiser pseudonymiser;
    private final NoticeCatalogue notice;
    private final Clock clock;
    private volatile Instant currentIssuedAt;

    @Autowired
    public NoticeAcknowledgementService(Database database, PrivacyKeys keys, Pseudonymiser pseudonymiser,
                                        NoticeCatalogue notice) {
        this(database, keys, pseudonymiser, notice, Clock.systemUTC());
    }

    NoticeAcknowledgementService(Database database, PrivacyKeys keys, Pseudonymiser pseudonymiser,
                                 NoticeCatalogue notice, Clock clock) {
        this.database = database;
        this.keys = keys;
        this.pseudonymiser = pseudonymiser;
        this.notice = notice;
        this.clock = clock;
    }

    public record Result(int accepted, int duplicates) {
    }

    /** The version shown from now on is issued at startup; an intake retries it when the database was not ready. */
    @EventListener(ApplicationReadyEvent.class)
    void issueAtStartup() {
        try {
            issueCurrent();
        } catch (RuntimeException e) {
            LOG.warn("the current notice version could not be issued yet: {}", e.getClass().getSimpleName());
        }
    }

    public Result record(List<AcknowledgementPayload> batch) {
        if (batch == null || batch.isEmpty()) {
            throw new BadRequest("INVALID_ACKNOWLEDGEMENT", "The body must be a non-empty JSON array.");
        }
        if (batch.size() > MAX_BATCH) {
            throw new BadRequest("INVALID_ACKNOWLEDGEMENT", "A batch holds at most " + MAX_BATCH + " records.");
        }
        String keyId = keys.keyId();
        String current = notice.currentVersion().orElseThrow(() -> new BadRequest("NOTICE_INCOMPLETE",
            "The notice is incomplete and is not shown, so nothing can be acknowledged; configure every "
                + "RWSAFE_ENDUSER_ value."));
        Instant currentIssuedAt = issueCurrent().orElseThrow();
        Map<String, Optional<Instant>> issued = new HashMap<>();
        issued.put(current, Optional.of(currentIssuedAt));
        Instant now = clock.instant();
        List<NoticeAcknowledgement> rows = new ArrayList<>(batch.size());
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < batch.size(); i++) {
            NoticeAcknowledgement row = validate(i, batch.get(i), now, keyId, current, issued);
            if (seen.add(row.userPseudonym() + "|" + row.noticeVersion() + "|" + row.source())) {
                rows.add(row);
            }
        }
        int inserted = database.noticeAcknowledgements().record(rows);
        return new Result(inserted, batch.size() - inserted);
    }

    /** The records of one pseudonym and whether the current notice is acknowledged. */
    public List<NoticeAcknowledgement> forUser(String userPseudonym) {
        return database.noticeAcknowledgements().forUser(userPseudonym);
    }

    /**
     * SR-PRIV-10: content may be captured for this user only when the current notice is complete and the user has an
     * acknowledgement of exactly its version from any source; otherwise metadata and verdict only. A user without a
     * pseudonym, an incomplete notice or an unreachable database answers false (fail closed).
     */
    public boolean contentCaptureAllowed(String userPseudonym) {
        Optional<String> version = notice.currentVersion();
        if (userPseudonym == null || version.isEmpty() || !pseudonym(userPseudonym)) {
            return false;
        }
        try {
            return database.noticeAcknowledgements().acknowledged(userPseudonym, version.get());
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** How many users acknowledged the current version; zero while the notice is incomplete. */
    public long usersAcknowledgedCurrent() {
        return notice.currentVersion().map(v -> database.noticeAcknowledgements().usersAcknowledged(v)).orElse(0L);
    }

    /**
     * Records the current version's issue time once (the first one stays across restarts) and caches it; empty while the
     * notice is incomplete. Called at startup and before every intake.
     */
    public Optional<Instant> issueCurrent() {
        Optional<String> version = notice.currentVersion();
        if (version.isEmpty()) {
            return Optional.empty();
        }
        Instant at = currentIssuedAt;
        if (at == null) {
            at = database.noticeAcknowledgements().issue(version.get(), clock.instant().truncatedTo(ChronoUnit.MICROS));
            currentIssuedAt = at;
        }
        return Optional.of(at);
    }

    /**
     * D-03: every record names a version this deployment issued and is dated from that issue (less the skew) to now (plus
     * the skew). An interactive source records the current version only; the directory import may carry an earlier
     * issued version, kept as history (it does not open content capture).
     */
    private NoticeAcknowledgement validate(int i, AcknowledgementPayload p, Instant now, String keyId, String current,
                                           Map<String, Optional<Instant>> issued) {
        if (p == null) {
            throw invalid(i, "record");
        }
        String claim = p.userClaim();
        if (claim == null || claim.isBlank() || claim.length() > 256) {
            throw invalid(i, "userClaim");
        }
        if (p.noticeVersion() == null || !noticeVersion(p.noticeVersion())) {
            throw invalid(i, "noticeVersion");
        }
        Instant at;
        try {
            at = Instant.parse(p.acknowledgedAt() == null ? "" : p.acknowledgedAt());
        } catch (DateTimeParseException e) {
            throw invalid(i, "acknowledgedAt");
        }
        if (p.source() == null || !SOURCES.contains(p.source())) {
            throw invalid(i, "source");
        }
        if (INTERACTIVE.contains(p.source()) && !p.noticeVersion().equals(current)) {
            throw invalid(i, "noticeVersion");
        }
        Optional<Instant> issuedAt = issued.computeIfAbsent(p.noticeVersion(),
            v -> database.noticeAcknowledgements().issuedAt(v));
        if (issuedAt.isEmpty()) {
            throw invalid(i, "noticeVersion");
        }
        if (at.isBefore(issuedAt.get().minus(MAX_SKEW)) || at.isAfter(now.plus(MAX_SKEW))) {
            throw invalid(i, "acknowledgedAt");
        }
        String user = pseudonymiser.user(claim);
        if (user == null) {
            throw invalid(i, "userClaim");
        }
        return new NoticeAcknowledgement(user, p.noticeVersion(), at, p.source(), null, keyId);
    }

    /** Names the element and the field, never the value. */
    private static BadRequest invalid(int i, String field) {
        return new BadRequest("INVALID_ACKNOWLEDGEMENT", "Record " + i + ": the field '" + field + "' is invalid.");
    }

    /** {@code tr-1-0a1b2c3d}: two lower-case letters, 1 to 4 digits, 8 lower-case hex (the V5 column check). */
    static boolean noticeVersion(String s) {
        int first = s.indexOf('-');
        int last = s.lastIndexOf('-');
        if (first != 2 || last == first || s.length() - last - 1 != 8 || last - first - 1 < 1 || last - first - 1 > 4) {
            return false;
        }
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            boolean ok;
            if (k < 2) {
                ok = c >= 'a' && c <= 'z';
            } else if (k == first || k == last) {
                ok = true;
            } else if (k < last) {
                ok = c >= '0' && c <= '9';
            } else {
                ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            }
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    static boolean pseudonym(String s) {
        if (s.length() != 14 || !s.startsWith("USR-")) {
            return false;
        }
        for (int k = 4; k < s.length(); k++) {
            char c = s.charAt(k);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }
}
