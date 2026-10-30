package io.rwsafe.control.capture;

import io.rwsafe.control.config.ControlProperties;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * The capture store's files (ADR-009 §2: the capture store, outside PostgreSQL), on their own volume
 * ({@code RWSAFE_CAPTURE_STORE_DIR}). One file per chunk, named by its random chunk id (never by content), holding
 * nonce || AES-GCM ciphertext || tag. A chunk is written to {@code tmp/} first and moved into place inside the database
 * transaction that creates its row; a file without a row (a rolled-back insert, a crash) is swept after an hour.
 */
@Component
public final class ChunkFiles {

    static final String SUFFIX = ".chunk";
    static final Duration ORPHAN_AGE = Duration.ofHours(1);

    private final Path dir;

    @Autowired
    public ChunkFiles(ControlProperties properties) {
        this(properties.capture().storeDir());
    }

    ChunkFiles(Path dir) {
        this.dir = dir;
    }

    public Path dir() {
        return dir;
    }

    /** True when the store directory exists or can be made, and is writable. */
    public boolean available() {
        try {
            Files.createDirectories(dir.resolve("tmp"));
            return Files.isWritable(dir) && Files.isWritable(dir.resolve("tmp"));
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    private Path temp(UUID id) {
        return dir.resolve("tmp").resolve(id + ".tmp");
    }

    private Path path(UUID id) {
        String s = id.toString();
        return dir.resolve(s.substring(0, 2)).resolve(s + SUFFIX);
    }

    /** Writes a new chunk's sealed bytes to its temporary file (synced). */
    void writeTemp(UUID id, byte[] sealed) {
        try {
            Files.createDirectories(dir.resolve("tmp"));
            try (var ch = java.nio.channels.FileChannel.open(temp(id), StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
                java.nio.ByteBuffer b = java.nio.ByteBuffer.wrap(sealed);
                while (b.hasRemaining()) {
                    ch.write(b);
                }
                ch.force(true);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("capture chunk not written", e);
        }
    }

    /** Moves a chunk into place (called inside the transaction that creates its row). */
    void commit(UUID id) {
        try {
            Files.createDirectories(path(id).getParent());
            Files.move(temp(id), path(id), StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException("capture chunk not moved into place", e);
        }
    }

    void deleteTemp(UUID id) {
        try {
            Files.deleteIfExists(temp(id));
        } catch (IOException e) {
            // Swept later.
        }
    }

    /** The sealed bytes of a chunk; null when the file is missing. */
    byte[] read(UUID id) {
        try {
            return Files.readAllBytes(path(id));
        } catch (IOException e) {
            return null;
        }
    }

    /** Deletes the files of chunks whose rows are gone; a file that cannot be deleted now is swept later. */
    int delete(Collection<UUID> ids) {
        int n = 0;
        for (UUID id : ids) {
            try {
                if (Files.deleteIfExists(path(id))) {
                    n++;
                }
            } catch (IOException e) {
                // Its data key is already gone with the row: the file is unreadable; the sweep removes it.
            }
        }
        return n;
    }

    /**
     * Deletes chunk files without a row and temporary files, both older than {@link #ORPHAN_AGE}; {@code known} answers
     * which chunk ids have rows.
     */
    int sweep(Function<Collection<UUID>, Set<UUID>> known, Instant now) {
        int n = 0;
        FileTime cutoff = FileTime.from(now.minus(ORPHAN_AGE));
        try {
            if (!Files.isDirectory(dir)) {
                return 0;
            }
            try (var files = Files.walk(dir, 2)) {
                List<Path> candidates = files.filter(Files::isRegularFile).filter(f -> old(f, cutoff)).toList();
                List<UUID> ids = new ArrayList<>();
                List<Path> chunkFiles = new ArrayList<>();
                for (Path f : candidates) {
                    String name = f.getFileName().toString();
                    if (name.endsWith(".tmp")) {
                        Files.deleteIfExists(f);
                        n++;
                    } else if (name.endsWith(SUFFIX)) {
                        try {
                            ids.add(UUID.fromString(name.substring(0, name.length() - SUFFIX.length())));
                            chunkFiles.add(f);
                        } catch (IllegalArgumentException e) {
                            // Not a file of ours: left alone.
                        }
                    }
                }
                for (int i = 0; i < ids.size(); i += 500) {
                    List<UUID> batch = ids.subList(i, Math.min(ids.size(), i + 500));
                    Set<UUID> keep = known.apply(batch);
                    for (int k = 0; k < batch.size(); k++) {
                        if (!keep.contains(batch.get(k))) {
                            Files.deleteIfExists(chunkFiles.get(i + k));
                            n++;
                        }
                    }
                }
            }
        } catch (IOException e) {
            return n;
        }
        return n;
    }

    private static boolean old(Path f, FileTime cutoff) {
        try {
            return Files.getLastModifiedTime(f).compareTo(cutoff) < 0;
        } catch (IOException e) {
            return false;
        }
    }
}
