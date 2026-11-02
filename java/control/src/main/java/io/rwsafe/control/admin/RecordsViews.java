package io.rwsafe.control.admin;

import io.rwsafe.control.ops.JobCatalog;
import io.rwsafe.control.ops.JobRuns;
import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.control.siem.SiemRecords;
import io.rwsafe.persistence.SiemExportStore.LedgerRow;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The bodies of Administration -> Records (PO decision Q-47 decision 1.3). The masked role never reaches these routes
 * (AccessRules {@code admin.audit.read} and {@code admin.access} refuse it); the masked projections exist for the
 * funnel's coverage rule and withhold every free value all the same.
 */
public final class RecordsViews {

    private RecordsViews() {
    }

    /**
     * One ledger row as the SIEM export shows it ({@link SiemRecords#ledgerEntry}): the actor's pseudonym or system
     * actor, the action id, the audited table and operation, the row key (a pseudonym for an account or any key that is
     * not of its table's exact shape) and the reason (a vocabulary token, or free text through the free-text masker).
     * The ledger has no column for a prompt, a response or a request body, so none can appear.
     */
    public record AuditEntryView(long id, Instant occurredAt, String actor, String action, String table,
                                 String operation, String rowKey, String reason) {

        static AuditEntryView of(LedgerRow row, SiemRecords.LedgerEntry e) {
            return new AuditEntryView(row.auditId(), row.occurredAt(), e.actor(), e.action(), e.table(), e.operation(),
                e.rowKey(), e.reason());
        }

        /** Never prints the reason or the row key. */
        @Override
        public String toString() {
            return "AuditEntryView[" + id + ", " + action + ", " + table + "]";
        }
    }

    /**
     * One page, newest first; {@code nextCursor} continues it (null: no older entry matches). {@code actions} are the
     * action ids the ledger holds (the action filter's choices; on a first page only, empty on a cursor page);
     * {@code from} and {@code to} the window applied.
     */
    public record AuditLogView(List<AuditEntryView> entries, String nextCursor, List<String> actions, Instant from,
                               Instant to, int limit) implements MaskedView {

        @Override
        public AuditLogView masked(TextMasker masker) {
            return new AuditLogView(entries.stream().map(e -> new AuditEntryView(e.id(), e.occurredAt(), e.actor(),
                e.action(), e.table(), e.operation(), TextMasker.WITHHELD, TextMasker.WITHHELD)).toList(), nextCursor,
                actions, from, to, limit);
        }
    }

    /** One finished run: times, ok or failed, a fixed failure code and counts under fixed keys. */
    public record RunView(Instant startedAt, Instant endedAt, boolean ok, String failure, Map<String, Long> counts) {

        static RunView of(JobRuns.Run r) {
            return new RunView(r.startedAt(), r.endedAt(), r.ok(), r.failure(), r.counts());
        }
    }

    /**
     * One job. {@code kind} is {@code FIXED_DELAY} (with {@code initialDelaySeconds} and {@code delaySeconds}),
     * {@code CRON} (with {@code cron} and {@code zone}) or {@code CONTINUOUS}. {@code state}: {@code OK}, {@code FAILED},
     * {@code RUNNING}, {@code NOT_RUN_YET}; for a continuous job the health state ({@code UP}, {@code DEGRADED},
     * {@code DOWN}, {@code UNKNOWN}). {@code runs} and {@code failures} count since the instance started; {@code recent}
     * holds the last runs, newest first.
     */
    public record JobView(String id, String kind, Long initialDelaySeconds, Long delaySeconds, String cron, String zone,
                          String state, Instant lastStartedAt, Instant lastEndedAt, String failure,
                          Map<String, Long> counts, Instant nextRunAt, long runs, long failures, List<RunView> recent) {

        static JobView of(JobCatalog.Job job, JobRuns.Log log, Instant next) {
            JobRuns.Run last = log.last();
            String state = log.runningSince() != null ? "RUNNING" : last == null ? "NOT_RUN_YET"
                : last.ok() ? "OK" : "FAILED";
            return new JobView(job.id(), job.kind().name(), seconds(job.initialDelay()), seconds(job.delay()), job.cron(),
                job.zone(), state, log.runningSince() != null ? log.runningSince()
                    : last == null ? null : last.startedAt(), last == null ? null : last.endedAt(),
                last == null ? null : last.failure(), last == null ? Map.of() : last.counts(), next, log.total(),
                log.failed(), log.runs().stream().map(RunView::of).toList());
        }

        private static Long seconds(java.time.Duration d) {
            return d == null ? null : d.toSeconds();
        }
    }

    /** {@code since}: when this instance (and so this log) started. */
    public record JobsView(Instant since, Instant checkedAt, List<JobView> jobs) implements MaskedView {

        @Override
        public JobsView masked(TextMasker masker) {
            return this;
        }
    }
}
