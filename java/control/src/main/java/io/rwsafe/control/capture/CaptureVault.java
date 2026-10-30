package io.rwsafe.control.capture;

import io.rwsafe.persistence.CaptureStore;
import io.rwsafe.persistence.CaptureStore.CaptureRecord;
import io.rwsafe.persistence.CaptureStore.ChunkPlan;
import io.rwsafe.persistence.CaptureStore.StoredChunk;
import io.rwsafe.persistence.Database;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/**
 * Seals and opens C3 records in the capture store (ADR-009 §2-§3). Sealing: the text is cut into content-defined chunks;
 * each chunk's keyed address is looked up and a repeated chunk is referenced, never written again; a new chunk is
 * encrypted with AES-256-GCM under a data key of its own (its address as associated data) into a file, and the data key
 * is wrapped under the capture key. The record gets its own key, wrapped likewise, whose HMAC binds the record's event
 * id, user, capture and expiry times, truncation flag, rule set, size and ordered chunk addresses (PR 25 review D-04).
 * Opening reverses it and fails closed on any mismatch. Plaintext buffers are zeroed after use.
 *
 * <p>Per-chunk rather than per-record data keys are what deduplication requires (a shared chunk cannot be sealed under
 * two records' keys); deleting a chunk's row, which holds its only wrapped data key, is its crypto-shredding.
 */
@Component
public final class CaptureVault {

    /** At most this many bytes of redacted text per record after masking (V8). */
    static final int MAX_PLAIN_BYTES = 262_144;

    private final CaptureKeyring keys;
    private final ChunkFiles files;
    private final Database database;

    public CaptureVault(CaptureKeyring keys, ChunkFiles files, Database database) {
        this.keys = keys;
        this.files = files;
        this.database = database;
    }

    /** A record whose new chunks are written to temporary files, ready to be stored. */
    public final class Prepared {

        private final List<ChunkPlan> plans;
        private final List<String> addresses;
        private final long newBytes;
        private boolean finished;

        private Prepared(List<ChunkPlan> plans, List<String> addresses, long newBytes) {
            this.plans = plans;
            this.addresses = addresses;
            this.newBytes = newBytes;
        }

        /** The bytes the new chunks add to the store (deduplicated chunks add none). */
        public long newBytes() {
            return newBytes;
        }

        /** Stores the record; false when the event already had one. Temporary files not taken into the store go. */
        public boolean store(UUID eventId, String userPseudonym, Instant capturedAt, Instant expiresAt, int plainBytes,
                             boolean truncated, String maskRuleSet) {
            try {
                byte[] recordKey = CaptureKeyring.newKey();
                try {
                    CaptureKeyring.Wrapped wrapped = keys.wrap(recordKey, recordPurpose(eventId));
                    CaptureRecord r = new CaptureRecord(eventId, micros(capturedAt), micros(expiresAt), userPseudonym,
                        wrapped.keyId(), wrapped.wrapped(), null, plainBytes, truncated, maskRuleSet, false);
                    byte[] mac = mac(recordKey, r, addresses);
                    r = new CaptureRecord(r.eventId(), r.capturedAt(), r.expiresAt(), r.userPseudonym(), r.keyId(),
                        r.wrappedKey(), mac, r.plainBytes(), r.truncated(), r.maskRuleSet(), false);
                    return database.captures().insert(r, plans, files::commit).stored();
                } finally {
                    Arrays.fill(recordKey, (byte) 0);
                }
            } finally {
                discard();
            }
        }

        /** Removes the temporary files of chunks the store did not take (always safe to call). */
        public void discard() {
            if (finished) {
                return;
            }
            finished = true;
            for (ChunkPlan p : plans) {
                if (p.wrappedKey() != null) {
                    files.deleteTemp(p.chunkId());
                }
            }
        }
    }

    /** Cuts, addresses and seals the new chunks of {@code plain[0, len)}; the caller zeroes {@code plain}. */
    public Prepared prepare(byte[] plain, int len) {
        List<int[]> cuts = Chunker.cut(plain, len);
        List<String> addresses = new ArrayList<>(cuts.size());
        for (int[] c : cuts) {
            addresses.add(keys.address(plain, c[0], c[1]));
        }
        Map<String, java.util.UUID> existing = database.captures().existingChunks(addresses);
        Map<String, ChunkPlan> byAddress = new LinkedHashMap<>();
        List<ChunkPlan> plans = new ArrayList<>(cuts.size());
        long newBytes = 0;
        try {
            for (int i = 0; i < cuts.size(); i++) {
                String address = addresses.get(i);
                ChunkPlan plan = byAddress.get(address);
                if (plan == null) {
                    if (existing.containsKey(address)) {
                        plan = new ChunkPlan(address, existing.get(address), null, null, 0);
                    } else {
                        plan = seal(plain, cuts.get(i), address);
                        newBytes += plan.storedBytes();
                    }
                    byAddress.put(address, plan);
                }
                plans.add(plan);
            }
        } catch (RuntimeException e) {
            for (ChunkPlan p : byAddress.values()) {
                if (p.wrappedKey() != null) {
                    files.deleteTemp(p.chunkId());
                }
            }
            throw e;
        }
        return new Prepared(plans, addresses, newBytes);
    }

    private ChunkPlan seal(byte[] plain, int[] cut, String address) {
        UUID id = UUID.randomUUID();
        byte[] dek = CaptureKeyring.newKey();
        byte[] part = Arrays.copyOfRange(plain, cut[0], cut[0] + cut[1]);
        try {
            byte[] nonce = CaptureKeyring.random(CaptureKeyring.NONCE_BYTES);
            byte[] ct = CaptureKeyring.gcm(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), nonce,
                chunkAad(address), part);
            byte[] sealed = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, sealed, 0, nonce.length);
            System.arraycopy(ct, 0, sealed, nonce.length, ct.length);
            files.writeTemp(id, sealed);
            CaptureKeyring.Wrapped wrapped = keys.wrap(dek, chunkPurpose(address));
            return new ChunkPlan(address, id, wrapped.keyId(), wrapped.wrapped(), sealed.length);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM unavailable", e);
        } finally {
            Arrays.fill(dek, (byte) 0);
            Arrays.fill(part, (byte) 0);
        }
    }

    /** Why a record did not open. */
    public enum Failure { KEY_UNAVAILABLE, INTEGRITY_FAILED }

    /** The opened text (the caller zeroes it), or why it did not open. */
    public record Opened(byte[] plain, Failure failure) {

        @Override
        public String toString() {
            return "Opened[" + (failure == null ? "ok" : failure) + "]";
        }
    }

    public Opened open(CaptureRecord r) {
        Optional<byte[]> recordKey = keys.unwrap(r.keyId(), r.wrappedKey(), recordPurpose(r.eventId()));
        if (recordKey.isEmpty()) {
            return new Opened(null, keys.has(r.keyId()) ? Failure.INTEGRITY_FAILED : Failure.KEY_UNAVAILABLE);
        }
        List<StoredChunk> chunks = database.captures().manifest(r.eventId());
        List<String> addresses = chunks.stream().map(StoredChunk::address).toList();
        try {
            if (!MessageDigest.isEqual(mac(recordKey.get(), r, addresses), r.manifestMac())) {
                return new Opened(null, Failure.INTEGRITY_FAILED);
            }
        } finally {
            Arrays.fill(recordKey.get(), (byte) 0);
        }
        byte[] out = new byte[r.plainBytes()];
        int at = 0;
        for (StoredChunk c : chunks) {
            Optional<byte[]> dek = keys.unwrap(c.keyId(), c.wrappedKey(), chunkPurpose(c.address()));
            if (dek.isEmpty()) {
                Arrays.fill(out, (byte) 0);
                return new Opened(null, keys.has(c.keyId()) ? Failure.INTEGRITY_FAILED : Failure.KEY_UNAVAILABLE);
            }
            byte[] sealed = files.read(c.chunkId());
            byte[] part = null;
            try {
                if (sealed == null || sealed.length <= CaptureKeyring.NONCE_BYTES) {
                    Arrays.fill(out, (byte) 0);
                    return new Opened(null, Failure.INTEGRITY_FAILED);
                }
                part = CaptureKeyring.gcm(Cipher.DECRYPT_MODE, new SecretKeySpec(dek.get(), "AES"),
                    Arrays.copyOf(sealed, CaptureKeyring.NONCE_BYTES), chunkAad(c.address()),
                    Arrays.copyOfRange(sealed, CaptureKeyring.NONCE_BYTES, sealed.length));
                if (at + part.length > out.length) {
                    Arrays.fill(out, (byte) 0);
                    return new Opened(null, Failure.INTEGRITY_FAILED);
                }
                System.arraycopy(part, 0, out, at, part.length);
                at += part.length;
            } catch (GeneralSecurityException e) {
                Arrays.fill(out, (byte) 0);
                return new Opened(null, Failure.INTEGRITY_FAILED);
            } finally {
                Arrays.fill(dek.get(), (byte) 0);
                if (part != null) {
                    Arrays.fill(part, (byte) 0);
                }
            }
        }
        if (at != out.length) {
            Arrays.fill(out, (byte) 0);
            return new Opened(null, Failure.INTEGRITY_FAILED);
        }
        return new Opened(out, null);
    }

    /** Deletes the files of chunks whose rows a deletion pass removed. */
    public void removeFiles(CaptureStore.Deleted deleted) {
        files.delete(deleted.chunkIds());
    }

    static String recordPurpose(UUID eventId) {
        return "record|" + eventId;
    }

    static String chunkPurpose(String address) {
        return "chunk|" + address;
    }

    private static byte[] chunkAad(String address) {
        return ("rwsafe-c3-chunk-v1|" + address).getBytes(StandardCharsets.US_ASCII);
    }

    static Instant micros(Instant t) {
        return t.truncatedTo(ChronoUnit.MICROS);
    }

    /** The record binding (D-04): every security-relevant column and the ordered chunk addresses. */
    static byte[] mac(byte[] recordKey, CaptureRecord r, List<String> addresses) {
        String canonical = "rwsafe-c3-record-v1|" + r.eventId() + "|" + r.userPseudonym() + "|"
            + ChronoUnit.MICROS.between(Instant.EPOCH, r.capturedAt()) + "|"
            + ChronoUnit.MICROS.between(Instant.EPOCH, r.expiresAt()) + "|" + r.truncated() + "|" + r.maskRuleSet() + "|"
            + r.plainBytes() + "|" + String.join(",", addresses);
        byte[] bytes = canonical.getBytes(StandardCharsets.US_ASCII);
        return CaptureKeyring.hmac(recordKey, bytes, 0, bytes.length);
    }
}
