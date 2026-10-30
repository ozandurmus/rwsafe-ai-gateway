package io.rwsafe.control.capture;

import io.rwsafe.persistence.CaptureStore;
import io.rwsafe.persistence.CaptureStore.CaptureRecord;
import io.rwsafe.persistence.CaptureStore.Rewrap;
import io.rwsafe.persistence.CaptureStore.StoredChunk;
import io.rwsafe.persistence.Database;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The C3 maintenance job (ADR-009 §3-§4, DATA_CLASSES_AND_RETENTION §2, PR 25 Q-3), in the protected windows (AGENTS.md
 * section 14: 00, 06, 12, 18 Europe/Istanbul), each step ledgered and receipted:
 * <ol>
 *   <li>retention: records past their expiry without a legal hold are deleted, and their unreferenced chunks;</li>
 *   <li>emergency crypto-shredding: for a key the Secret lists as {@code shredded} (and no longer uses), the records under
 *       it are deleted with an {@code EMERGENCY_SHRED} key event; held ones stay, unreadable, and are reported;</li>
 *   <li>planned rotation: records within retention or on hold, and the chunks they reference, still wrapped under an
 *       older key are re-wrapped under the active key (the content is never decrypted), as {@code REWRAP} key events;
 *       the old key may be removed once Health shows nothing left under it;</li>
 *   <li>the byte cap: the oldest records are evicted until the store fits MAX_STORE_BYTES;</li>
 *   <li>files without a row older than an hour are swept.</li>
 * </ol>
 */
@Component
public class CaptureRetentionJob {

    private static final Logger LOG = LoggerFactory.getLogger(CaptureRetentionJob.class);
    private static final int MAX_PASSES = 100;
    private static final int REWRAP_BATCH = 500;

    private final Database database;
    private final CaptureKeyring keys;
    private final CaptureVault vault;
    private final StoreCap cap;
    private final ChunkFiles files;
    private final Clock clock;

    @Autowired
    public CaptureRetentionJob(Database database, CaptureKeyring keys, CaptureVault vault, StoreCap cap,
                               ChunkFiles files) {
        this(database, keys, vault, cap, files, Clock.systemUTC());
    }

    CaptureRetentionJob(Database database, CaptureKeyring keys, CaptureVault vault, StoreCap cap, ChunkFiles files,
                        Clock clock) {
        this.database = database;
        this.keys = keys;
        this.vault = vault;
        this.cap = cap;
        this.files = files;
        this.clock = clock;
    }

    /** What one run did. {@code stranded}: rows under an older key that is no longer mounted (cannot be re-wrapped). */
    public record Run(int expired, int shredded, int rewrapped, int stranded, boolean capMet, int sweptFiles) {
    }

    @Scheduled(cron = "0 20 0,6,12,18 * * *", zone = "Europe/Istanbul")
    public void scheduled() {
        try {
            Run r = runOnce();
            LOG.info("capture maintenance: {} expired, {} shredded, {} re-wrapped, {} stranded, cap met {}, {} files "
                + "swept", r.expired(), r.shredded(), r.rewrapped(), r.stranded(), r.capMet(), r.sweptFiles());
        } catch (RuntimeException e) {
            LOG.warn("capture maintenance failed: {}", e.getClass().getSimpleName());
        }
    }

    public Run runOnce() {
        keys.reload();
        Instant now = clock.instant();
        int expired = drain(() -> database.captures().deleteExpired(now));
        int shredded = 0;
        Set<String> inUse = database.captures().keysInUse();
        for (String k : keys.shredded()) {
            if (inUse.contains(k)) {
                shredded += drain(() -> database.captures().deleteShredded(k));
            }
        }
        int[] rewrap = rewrap(now);
        boolean capMet = cap.makeRoom(0);
        int swept = files.sweep(database.captures()::knownChunks, now);
        return new Run(expired, shredded, rewrap[0], rewrap[1], capMet, swept);
    }

    /** Planned rotation (Q-3): re-wraps under the active key what is still under another; returns {re-wrapped, stranded}. */
    int[] rewrap(Instant now) {
        Optional<String> active = keys.activeId();
        if (active.isEmpty()) {
            return new int[] {0, 0};
        }
        // D-09: only mounted keys other than the active one can be re-wrapped from; rows under an unmounted or shredded
        // key are never selected, so they cannot fill a page and starve the rotation (Health reports them apart).
        Set<String> from = new TreeSet<>(keys.ids());
        from.remove(active.get());
        if (from.isEmpty()) {
            return new int[] {0, 0};
        }
        int done = 0;
        Set<String> skipped = new TreeSet<>();
        int stranded = 0;
        for (int pass = 0; pass < MAX_PASSES; pass++) {
            List<Rewrap> records = new ArrayList<>();
            int seen = 0;
            for (CaptureRecord r : database.captures().recordsToRewrap(from, now, REWRAP_BATCH)) {
                seen++;
                Optional<CaptureKeyring.Wrapped> w = keys.rewrap(r.keyId(), r.wrappedKey(),
                    CaptureVault.recordPurpose(r.eventId()));
                if (w.isPresent()) {
                    records.add(new Rewrap(r.eventId(), r.keyId(), w.get().keyId(), w.get().wrapped()));
                } else if (skipped.add("r" + r.eventId())) {
                    stranded++;
                }
            }
            List<Rewrap> chunks = new ArrayList<>();
            for (StoredChunk c : database.captures().chunksToRewrap(from, REWRAP_BATCH)) {
                seen++;
                Optional<CaptureKeyring.Wrapped> w = keys.rewrap(c.keyId(), c.wrappedKey(),
                    CaptureVault.chunkPurpose(c.address()));
                if (w.isPresent()) {
                    chunks.add(new Rewrap(c.chunkId(), c.keyId(), w.get().keyId(), w.get().wrapped()));
                } else if (skipped.add("c" + c.chunkId())) {
                    stranded++;
                }
            }
            int n = database.captures().applyRewrap(records, chunks);
            done += n;
            if (n == 0 || seen < REWRAP_BATCH) {
                break;
            }
        }
        return new int[] {done, stranded};
    }

    private int drain(java.util.function.Supplier<CaptureStore.Deleted> pass) {
        int total = 0;
        for (int i = 0; i < MAX_PASSES; i++) {
            CaptureStore.Deleted d = pass.get();
            vault.removeFiles(d);
            total += d.records();
            if (d.records() < CaptureStore.MAX_DELETE) {
                break;
            }
        }
        return total;
    }
}
