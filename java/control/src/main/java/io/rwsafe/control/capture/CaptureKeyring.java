package io.rwsafe.control.capture;

import io.rwsafe.control.config.ControlProperties;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The capture keys (ADR-009 §2, AGENTS.md 4.13): rwsafe's own Secret, separate from the privacy HMAC key and the snapshot
 * signing key. Envelope encryption: every record gets a fresh 256-bit data key that encrypts its text with AES-GCM; the
 * data key is wrapped with AES-GCM under the active capture key; both bind the event id as associated data, so a
 * ciphertext cannot be moved to another record. Only key ids reach the database or a log.
 *
 * <p>The Secret holds one {@code <key id>.key} file per key (base64 of exactly 32 bytes) and an {@code active} file naming
 * the key new records use (with one key, that key). Rotation: mount a new key and point {@code active} at it; old records
 * stay readable while the old key is mounted. Crypto-shredding: remove the old key from the Secret; its records can no
 * longer be opened by anyone, and the retention job deletes their rows with a receipt. The directory is re-read every 5
 * minutes. Kubernetes' own {@code ..data} entries are skipped.
 */
@Component
public final class CaptureKeyring {

    static final int KEY_BYTES = 32;
    static final int NONCE_BYTES = 12;
    static final int TAG_BITS = 128;
    private static final Logger LOG = LoggerFactory.getLogger(CaptureKeyring.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    /** One sealed text: the key it is under, the wrapped data key, the nonce and the ciphertext with its tag. */
    public record Sealed(String keyId, byte[] wrappedKey, byte[] nonce, byte[] ciphertext) {

        @Override
        public String toString() {
            return "Sealed[" + keyId + "]";
        }
    }

    private final Path dir;
    private volatile Map<String, SecretKeySpec> keys = Map.of();
    private volatile String activeId;
    private volatile String unavailableReason = "not loaded";

    @Autowired
    public CaptureKeyring(ControlProperties properties) {
        this(properties.capture().keyDir());
    }

    CaptureKeyring(Path dir) {
        this.dir = dir;
        reload();
    }

    /** Re-reads the Secret (rotation and shredding take effect without a restart). */
    @Scheduled(initialDelayString = "PT5M", fixedDelayString = "PT5M")
    public synchronized void reload() {
        Map<String, SecretKeySpec> loaded = new HashMap<>();
        String active = null;
        String reason = null;
        if (dir == null || !Files.isDirectory(dir)) {
            reason = "capture key directory not mounted";
        } else {
            try (var files = Files.list(dir)) {
                for (Path f : (Iterable<Path>) files::iterator) {
                    String name = f.getFileName().toString();
                    if (name.startsWith("..") || !name.endsWith(".key") || !Files.isRegularFile(f)) {
                        continue;
                    }
                    String id = name.substring(0, name.length() - ".key".length());
                    byte[] key = decode(Files.readString(f, StandardCharsets.US_ASCII));
                    if (!keyId(id) || key == null) {
                        reason = "a capture key file is not a key id with base64 of 32 bytes";
                        continue;
                    }
                    loaded.put(id, new SecretKeySpec(key, "AES"));
                    Arrays.fill(key, (byte) 0);
                }
                Path activeFile = dir.resolve("active");
                if (Files.isRegularFile(activeFile)) {
                    active = Files.readString(activeFile, StandardCharsets.US_ASCII).strip();
                } else if (loaded.size() == 1) {
                    active = loaded.keySet().iterator().next();
                }
            } catch (IOException e) {
                reason = "capture key directory unreadable";
            }
            if (active == null || !loaded.containsKey(active)) {
                reason = loaded.isEmpty() ? "no capture key mounted" : "the active capture key is not mounted";
                active = null;
            }
        }
        boolean changed = !loaded.keySet().equals(keys.keySet()) || !java.util.Objects.equals(active, activeId);
        keys = Map.copyOf(loaded);
        activeId = active;
        unavailableReason = active == null ? (reason == null ? "no capture key" : reason) : null;
        if (changed) {
            // Key ids only, never key material.
            LOG.info("capture keys: {} mounted, active {}", loaded.size(), active == null ? "none" : active);
        }
    }

    /** True when new records can be sealed. */
    public boolean available() {
        return activeId != null;
    }

    public String unavailableReason() {
        return unavailableReason;
    }

    public Optional<String> activeId() {
        return Optional.ofNullable(activeId);
    }

    /** The mounted key ids (a record under another id is shredded). */
    public Set<String> ids() {
        return new TreeSet<>(keys.keySet());
    }

    public boolean has(String keyId) {
        return keys.containsKey(keyId);
    }

    /** Seals {@code plain} under a fresh data key wrapped by the active key; {@code aad} binds the record. */
    public Sealed seal(byte[] plain, byte[] aad) {
        String id = activeId;
        SecretKeySpec kek = id == null ? null : keys.get(id);
        if (kek == null) {
            throw new IllegalStateException("no active capture key");
        }
        byte[] dek = new byte[KEY_BYTES];
        RANDOM.nextBytes(dek);
        try {
            byte[] nonce = random(NONCE_BYTES);
            byte[] ciphertext = gcm(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), nonce, aad, plain);
            byte[] wrapNonce = random(NONCE_BYTES);
            byte[] wrapped = gcm(Cipher.ENCRYPT_MODE, kek, wrapNonce, wrapAad(id, aad), dek);
            byte[] wrappedKey = new byte[NONCE_BYTES + wrapped.length];
            System.arraycopy(wrapNonce, 0, wrappedKey, 0, NONCE_BYTES);
            System.arraycopy(wrapped, 0, wrappedKey, NONCE_BYTES, wrapped.length);
            return new Sealed(id, wrappedKey, nonce, ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM unavailable", e);
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    /**
     * Opens a sealed text; empty when its key is not mounted (shredded) or the record does not authenticate (tampered,
     * moved to another event).
     */
    public Optional<byte[]> open(String keyId, byte[] wrappedKey, byte[] nonce, byte[] ciphertext, byte[] aad) {
        SecretKeySpec kek = keys.get(keyId);
        if (kek == null || wrappedKey.length <= NONCE_BYTES) {
            return Optional.empty();
        }
        byte[] dek = null;
        try {
            dek = gcm(Cipher.DECRYPT_MODE, kek, Arrays.copyOf(wrappedKey, NONCE_BYTES), wrapAad(keyId, aad),
                Arrays.copyOfRange(wrappedKey, NONCE_BYTES, wrappedKey.length));
            return Optional.of(gcm(Cipher.DECRYPT_MODE, new SecretKeySpec(dek, "AES"), nonce, aad, ciphertext));
        } catch (GeneralSecurityException e) {
            return Optional.empty();
        } finally {
            if (dek != null) {
                Arrays.fill(dek, (byte) 0);
            }
        }
    }

    private static byte[] gcm(int mode, SecretKeySpec key, byte[] nonce, byte[] aad, byte[] input)
        throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, key, new GCMParameterSpec(TAG_BITS, nonce));
        c.updateAAD(aad);
        return c.doFinal(input);
    }

    private static byte[] wrapAad(String keyId, byte[] aad) {
        byte[] id = ("rwsafe-capture-key|" + keyId + "|").getBytes(StandardCharsets.US_ASCII);
        byte[] out = Arrays.copyOf(id, id.length + aad.length);
        System.arraycopy(aad, 0, out, id.length, aad.length);
        return out;
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static byte[] decode(String text) {
        try {
            byte[] key = Base64.getDecoder().decode(text.strip());
            return key.length == KEY_BYTES ? key : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    static boolean keyId(String s) {
        if (s.isEmpty() || s.length() > 32) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
                return false;
            }
        }
        return true;
    }
}
