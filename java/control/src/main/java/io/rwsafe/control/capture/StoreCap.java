package io.rwsafe.control.capture;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.persistence.CaptureStore;
import io.rwsafe.persistence.Database;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * The capture store's byte cap (ADR-009 §3, MAX_STORE_BYTES, 80 GiB by default): before new chunks are stored, and in
 * every retention run, the oldest records without a legal hold are evicted until the store fits; each pass writes a
 * {@code STORE_CAP_EVICTED} receipt and every deleted row is ledgered. Evictions are counted for the Health screen. When
 * held records alone fill the cap, nothing new is stored.
 */
@Component
public final class StoreCap {

    static final int EVICT_BATCH = 100;
    static final int MAX_PASSES = 20;

    private final long maxBytes;
    private final Database database;
    private final CaptureVault vault;
    private final AtomicLong evicted = new AtomicLong();

    @Autowired
    public StoreCap(ControlProperties properties, Database database, CaptureVault vault) {
        this(properties.capture().maxStoreBytes(), database, vault);
    }

    StoreCap(long maxBytes, Database database, CaptureVault vault) {
        this.maxBytes = maxBytes;
        this.database = database;
        this.vault = vault;
    }

    /** Evicts oldest-first until {@code needed} more bytes fit; false when they cannot. */
    public synchronized boolean makeRoom(long needed) {
        if (needed > maxBytes) {
            return false;
        }
        for (int pass = 0; pass < MAX_PASSES; pass++) {
            if (database.captures().usage() + needed <= maxBytes) {
                return true;
            }
            CaptureStore.Deleted d = database.captures().evictOldest(EVICT_BATCH);
            vault.removeFiles(d);
            evicted.addAndGet(d.records());
            if (d.records() == 0) {
                return false;
            }
        }
        return database.captures().usage() + needed <= maxBytes;
    }

    public long maxBytes() {
        return maxBytes;
    }

    /** Records evicted for the cap since start. */
    public long evicted() {
        return evicted.get();
    }
}
