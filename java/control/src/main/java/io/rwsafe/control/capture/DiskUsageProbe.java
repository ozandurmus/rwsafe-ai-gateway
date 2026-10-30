package io.rwsafe.control.capture;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.stereotype.Component;

/**
 * Reads how full a filesystem is: {@code statvfs} through {@link FileStore} (CAPACITY §2, PLAT-F7: no kubelet API, no
 * cluster RBAC). NaN when the path cannot be read; the breaker then counts no reading and trips after 5 minutes.
 */
@Component
public class DiskUsageProbe {

    /** The used fraction {@code 0..1} of the filesystem holding {@code path} (its nearest existing ancestor), or NaN. */
    public double usedFraction(Path path) {
        Path p = path == null ? null : path.toAbsolutePath();
        while (p != null && !Files.exists(p)) {
            p = p.getParent();
        }
        if (p == null) {
            return Double.NaN;
        }
        try {
            FileStore store = Files.getFileStore(p);
            long total = store.getTotalSpace();
            return total <= 0 ? Double.NaN : 1.0 - (double) store.getUsableSpace() / total;
        } catch (IOException | SecurityException e) {
            return Double.NaN;
        }
    }
}
