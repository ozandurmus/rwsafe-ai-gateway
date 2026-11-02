package io.rwsafe.control.admin;

import io.rwsafe.control.admin.RecordsViews.AuditEntryView;
import io.rwsafe.control.admin.RecordsViews.AuditLogView;
import io.rwsafe.control.admin.RecordsViews.JobView;
import io.rwsafe.control.admin.RecordsViews.JobsView;
import io.rwsafe.control.api.ApiExceptionHandler.BadRequest;
import io.rwsafe.control.ops.JobCatalog;
import io.rwsafe.control.ops.JobRuns;
import io.rwsafe.control.privacy.Masking;
import io.rwsafe.control.privacy.MaskingUnavailableException;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.siem.SiemExportService;
import io.rwsafe.control.siem.SiemRecords;
import io.rwsafe.persistence.AuditLedgerQueries;
import io.rwsafe.persistence.AuditLedgerQueries.LedgerFilter;
import io.rwsafe.persistence.AuditLedgerQueries.LedgerPage;
import io.rwsafe.persistence.Database;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administration -> Records (PO decision Q-47 decision 1.3): the audit ledger and the scheduled-job log, read only.
 * The audit log is read by a {@code security_admin} or a {@code privacy_officer} (AccessRules {@code admin.audit.read});
 * the job log by a {@code security_admin} ({@code admin.access}); a masked session is refused 403 by the chain on both.
 *
 * <p>The audit log shows each ledger row exactly as the SIEM export does ({@link SiemRecords#ledgerEntry}): the actor
 * stays the pseudonym the ledger stores (a pseudonym is a keyed one-way digest; no rule maps it back to a name), an
 * account key becomes its pseudonym, and a reason that is not a vocabulary token passes the free-text masker. Without
 * the privacy key, the estate dictionary or the name dictionary the page is refused with 503 before any row is read
 * (AGENTS.md 4.10, PR 51 review D-01): what may be shown could not be decided.
 */
@RestController
@RequestMapping("/api/v1/admin")
public class RecordsAdminController {

    static final Duration DEFAULT_WINDOW = Duration.ofDays(30);
    static final Duration MAX_WINDOW = Duration.ofDays(366);
    static final int DEFAULT_PAGE = 50;

    private final Database database;
    private final PrivacyKeys keys;
    private final Pseudonymiser pseudonymiser;
    private final Masking masking;
    private final JobRuns runs;
    private final SiemExportService siem;
    private final AuditActionCache actionIds;
    private final Clock clock;

    public RecordsAdminController(Database database, PrivacyKeys keys, Pseudonymiser pseudonymiser, Masking masking,
                                  JobRuns runs, SiemExportService siem) {
        this.database = database;
        this.keys = keys;
        this.pseudonymiser = pseudonymiser;
        this.masking = masking;
        this.runs = runs;
        this.siem = siem;
        this.clock = Clock.systemUTC();
        this.actionIds = new AuditActionCache(() -> database.auditLedger().actionIds(), clock);
    }

    @GetMapping("/audit")
    public AuditLogView audit(@RequestParam(name = "from", required = false) Instant from,
                              @RequestParam(name = "to", required = false) Instant to,
                              @RequestParam(name = "action", required = false) String action,
                              @RequestParam(name = "actor", required = false) String actor,
                              @RequestParam(name = "limit", defaultValue = "50") int limit,
                              @RequestParam(name = "cursor", required = false) String cursor) {
        // Fail closed first (AGENTS.md 4.10, PR 51 review D-01): without the privacy key, the estate dictionary or the
        // name dictionary what may be shown cannot be decided, so the request is refused before any row is read.
        if (!keys.keyAvailable() || !keys.maskingAvailable() || !masking.available()) {
            throw new MaskingUnavailableException("audit log");
        }
        Instant end = to == null ? clock.instant() : to;
        Instant start = from == null ? end.minus(DEFAULT_WINDOW) : from;
        if (!start.isBefore(end)) {
            throw new BadRequest("INVALID_WINDOW", "'from' must be before 'to'.");
        }
        if (Duration.between(start, end).compareTo(MAX_WINDOW) > 0) {
            throw new BadRequest("WINDOW_TOO_LONG", "The window is at most 366 days.");
        }
        if (limit < 1 || limit > AuditLedgerQueries.MAX_PAGE) {
            throw new BadRequest("INVALID_LIMIT", "The limit is between 1 and " + AuditLedgerQueries.MAX_PAGE + ".");
        }
        // Every filter takes a vocabulary value or a pseudonym, never a name to test guesses with (SR-PRIV-4).
        SiemRecords records = records();
        if (action != null && !records.exportableAction(action)) {
            throw new BadRequest("INVALID_ACTION_FILTER", "The action filter takes an action id of the ledger.");
        }
        if (actor != null && !actor(actor)) {
            throw new BadRequest("INVALID_ACTOR_FILTER",
                "The actor filter takes a USR- pseudonym or a system actor only; real names are never searchable here.");
        }
        Long before = null;
        if (cursor != null) {
            // PR 51 review D-02: digits only, within a long, and a ledger id (the identity starts at 1).
            try {
                before = cursor.isEmpty() || cursor.length() > 19
                    || !cursor.chars().allMatch(c -> c >= '0' && c <= '9') ? null : Long.parseLong(cursor);
            } catch (NumberFormatException overflow) {
                before = null;
            }
            if (before == null || before <= 0) {
                throw new BadRequest("INVALID_CURSOR", "The page cursor is not one this server issued.");
            }
        }
        LedgerPage page = database.auditLedger().page(new LedgerFilter(start, end, action, actor, limit, before));
        List<AuditEntryView> entries = page.rows().stream()
            .map(r -> AuditEntryView.of(r, records.ledgerEntry(r))).toList();
        // The filter's choices only on a first page, from a short cache (PR 51 review D-04, AuditActionCache).
        List<String> actions = before != null ? List.of()
            : actionIds.actions().stream().filter(records::exportableAction).toList();
        return new AuditLogView(entries, page.nextBefore() == null ? null : Long.toString(page.nextBefore()), actions,
            start, end, limit);
    }

    @GetMapping("/jobs")
    public JobsView jobs() {
        Instant now = clock.instant();
        List<JobView> jobs = new ArrayList<>();
        for (JobCatalog.Job job : JobCatalog.JOBS) {
            if (job.kind() == JobCatalog.Kind.CONTINUOUS) {
                jobs.add(siemJob(job));
            } else {
                JobRuns.Log log = runs.log(job.id());
                jobs.add(JobView.of(job, log, JobCatalog.nextRun(job, runs.since(), log, now)));
            }
        }
        return new JobsView(runs.since(), now, jobs);
    }

    /**
     * The SIEM export runs continuously: its health state ({@code OFF} when the export is off), the latest acknowledged
     * batch and its counts.
     */
    private JobView siemJob(JobCatalog.Job job) {
        SiemExportService.Health h = siem.health();
        Map<String, Long> counts = new LinkedHashMap<>(h.counts());
        Instant last = siem.lastDelivery().orElse(null);
        // The health state UNKNOWN means the export is off (SiemExportService.Health).
        String state = "UNKNOWN".equals(h.state()) ? "OFF" : h.state();
        return new JobView(job.id(), job.kind().name(), null, null, null, null, state, null, last, null, counts, null,
            0, 0, List.of());
    }

    private SiemRecords records() {
        return new SiemRecords(pseudonymiser::user, key -> pseudonymiser.token("KEY", key), keys.estateTerms(),
            masking.masker()::maskFreeText);
    }

    /** {@code USR-<10 hex>} or {@code system:<name>}: the ledger's actor shapes (the audit trigger refuses others). */
    static boolean actor(String s) {
        if (s.startsWith("system:")) {
            String name = s.substring("system:".length());
            return !name.isEmpty() && name.length() <= 32
                && name.chars().allMatch(c -> (c >= 'a' && c <= 'z') || c == '_' || c == '-');
        }
        return s.length() == 14 && s.startsWith("USR-")
            && s.substring(4).chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}
