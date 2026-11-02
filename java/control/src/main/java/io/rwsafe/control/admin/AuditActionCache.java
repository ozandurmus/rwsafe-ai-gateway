package io.rwsafe.control.admin;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.Supplier;

/**
 * The audit log's action-filter choices (PR 51 review D-04): the distinct action ids of the ledger, read at most once per
 * {@link #TTL} per instance and only for a first page, never for a cursor page.
 *
 * <p>Why a short cache and not the request's time range: {@code audit_event} has no index on {@code occurred_at} (only
 * its key and the SIEM export's {@code (tx_id, audit_id)}), so a time-scoped {@code DISTINCT} would still read the whole
 * table on every request; adding the index needs a migration this slice avoids. The cache bounds the scan to one per
 * minute whatever the request rate. Action ids are code vocabulary (at most a few dozen, capped at 200), and a new one
 * appears only when a change of a new kind is first made; it is offered at most {@link #TTL} later. An action filter is
 * validated by its shape, not by this list, so a stale list never refuses a valid filter.
 */
final class AuditActionCache {

    static final Duration TTL = Duration.ofSeconds(60);

    private record Entry(Instant loadedAt, List<String> actions) {
    }

    private final Supplier<List<String>> loader;
    private final Clock clock;
    private Entry entry;

    AuditActionCache(Supplier<List<String>> loader, Clock clock) {
        this.loader = loader;
        this.clock = clock;
    }

    synchronized List<String> actions() {
        Instant now = clock.instant();
        if (entry == null || !now.isBefore(entry.loadedAt().plus(TTL))) {
            entry = new Entry(now, List.copyOf(loader.get()));
        }
        return entry.actions();
    }
}
