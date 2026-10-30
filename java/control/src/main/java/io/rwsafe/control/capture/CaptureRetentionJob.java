package io.rwsafe.control.capture;

import io.rwsafe.persistence.CaptureStore;
import io.rwsafe.persistence.Database;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The C3 deletion job (ADR-009 §4, DATA_CLASSES_AND_RETENTION §2): deletes records past their retention (90 days, Q-5)
 * that carry no legal hold, and the records under a capture key that is no longer mounted (crypto-shredded by rotation),
 * each pass with a receipt and ledgered. It runs in the protected windows (AGENTS.md section 14: 00, 06, 12, 18
 * Europe/Istanbul) and drains in passes of {@link CaptureStore#MAX_DELETE}.
 */
@Component
public class CaptureRetentionJob {

    private static final Logger LOG = LoggerFactory.getLogger(CaptureRetentionJob.class);
    private static final int MAX_PASSES = 100;

    private final Database database;
    private final CaptureKeyring keys;
    private final Clock clock;

    @Autowired
    public CaptureRetentionJob(Database database, CaptureKeyring keys) {
        this(database, keys, Clock.systemUTC());
    }

    CaptureRetentionJob(Database database, CaptureKeyring keys, Clock clock) {
        this.database = database;
        this.keys = keys;
        this.clock = clock;
    }

    /** What one run deleted. */
    public record Run(int expired, int shredded) {
    }

    @Scheduled(cron = "0 20 0,6,12,18 * * *", zone = "Europe/Istanbul")
    public void scheduled() {
        try {
            Run r = runOnce();
            LOG.info("capture retention: {} expired and {} shredded records deleted", r.expired(), r.shredded());
        } catch (RuntimeException e) {
            LOG.warn("capture retention failed: {}", e.getClass().getSimpleName());
        }
    }

    public Run runOnce() {
        keys.reload();
        Instant now = clock.instant();
        int expired = drain(() -> database.captures().deleteExpired(now));
        // Shredding needs evidence of a rotation: at least one mounted key (CaptureStore.deleteShredded).
        int shredded = keys.available() ? drain(() -> database.captures().deleteShredded(keys.ids())) : 0;
        return new Run(expired, shredded);
    }

    private static int drain(java.util.function.IntSupplier pass) {
        int total = 0;
        for (int i = 0; i < MAX_PASSES; i++) {
            int n = pass.getAsInt();
            total += n;
            if (n < CaptureStore.MAX_DELETE) {
                break;
            }
        }
        return total;
    }
}
