package io.rwsafe.control.capture;

import io.rwsafe.control.config.ControlProperties;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The capture keys (ADR-009 §2, AGENTS.md 4.13): rwsafe's own Secret, separate from the privacy HMAC key and the snapshot
 * signing key. Every chunk and every record has a fresh 256-bit key of its own; the capture key only wraps those keys
 * (AES-GCM, the key id and the wrapped key's purpose as associated data) and derives the keyed chunk address. Only key
 * ids reach the database or a log.
 *
 * <p>The Secret holds one {@code <key id>.key} file per key (base64 of exactly 32 bytes), an {@code active} file naming
 * the key new material is wrapped under (with one key, that key), and optionally a {@code shredded} file listing, one per
 * line, key ids deliberately destroyed without re-wrap (emergency crypto-shredding, PR 25 Q-3). A planned rotation mounts
 * a new key, points {@code active} at it and lets the re-wrap job move every live record and chunk over; only then is the
 * old key removed. The directory is re-read every 5 minutes. Kubernetes' own {@code ..data} entries are skipped.
 */
@Component
public final class CaptureKeyring {

    static final int KEY_BYTES = 32;
    static final int NONCE_BYTES = 12;
    static final int TAG_BITS = 128;
    /** nonce || GCM(capture key, 32-byte key) || tag. */
    static final int WRAPPED_BYTES = NONCE_BYTES + KEY_BYTES + 16;
    private static final Logger LOG = LoggerFactory.getLogger(CaptureKeyring.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    /** A key wrapped under {@code keyId}. */
    public record Wrapped(String keyId, byte[] wrapped) {

        @Override
        public String toString() {
            return "Wrapped[" + keyId + "]";
        }
    }

    private final Path dir;
    private volatile Map<String, SecretKeySpec> keys = Map.of();
    private volatile Set<String> shredded = Set.of();
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
        Set<String> shreddedIds = new TreeSet<>();
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
                Path shreddedFile = dir.resolve("shredded");
                if (Files.isRegularFile(shreddedFile)) {
                    for (String line : Files.readAllLines(shreddedFile, StandardCharsets.US_ASCII)) {
                        String id = line.strip();
                        if (keyId(id)) {
                            shreddedIds.add(id);
                        }
                    }
                }
            } catch (IOException e) {
                reason = "capture key directory unreadable";
            }
            if (active == null || !loaded.containsKey(active) || shreddedIds.contains(active)) {
                reason = loaded.isEmpty() ? "no capture key mounted" : "the active capture key is not usable";
                active = null;
            }
        }
        // A key listed as shredded is never used, even if its file is still mounted.
        loaded.keySet().removeAll(shreddedIds);
        boolean changed = !loaded.keySet().equals(keys.keySet()) || !Objects.equals(active, activeId)
            || !shreddedIds.equals(shredded);
        keys = Map.copyOf(loaded);
        shredded = Set.copyOf(shreddedIds);
        activeId = active;
        unavailableReason = active == null ? (reason == null ? "no capture key" : reason) : null;
        if (changed) {
            // Key ids only, never key material.
            LOG.info("capture keys: {} mounted, active {}, {} listed as shredded", loaded.size(),
                active == null ? "none" : active, shreddedIds.size());
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

    /** The mounted key ids. */
    public Set<String> ids() {
        return new TreeSet<>(keys.keySet());
    }

    /** Key ids the Secret lists as deliberately destroyed (emergency crypto-shredding). */
    public Set<String> shredded() {
        return shredded;
    }

    public boolean has(String keyId) {
        return keys.containsKey(keyId);
    }

    /** A fresh random 256-bit key (a chunk's data key or a record key); the caller zeroes it after use. */
    public static byte[] newKey() {
        byte[] k = new byte[KEY_BYTES];
        RANDOM.nextBytes(k);
        return k;
    }

    /** Wraps {@code key} under the active capture key; {@code purpose} binds what the key is for. */
    public Wrapped wrap(byte[] key, String purpose) {
        String id = activeId;
        SecretKeySpec kek = id == null ? null : keys.get(id);
        if (kek == null) {
            throw new IllegalStateException("no active capture key");
        }
        try {
            byte[] nonce = random(NONCE_BYTES);
            byte[] sealed = gcm(Cipher.ENCRYPT_MODE, kek, nonce, wrapAad(id, purpose), key);
            byte[] out = new byte[NONCE_BYTES + sealed.length];
            System.arraycopy(nonce, 0, out, 0, NONCE_BYTES);
            System.arraycopy(sealed, 0, out, NONCE_BYTES, sealed.length);
            return new Wrapped(id, out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM unavailable", e);
        }
    }

    /** The key {@code wrapped} holds; empty when its capture key is not mounted or the wrapping does not authenticate. */
    public Optional<byte[]> unwrap(String keyId, byte[] wrapped, String purpose) {
        SecretKeySpec kek = keys.get(keyId);
        if (kek == null || wrapped.length != WRAPPED_BYTES) {
            return Optional.empty();
        }
        try {
            return Optional.of(gcm(Cipher.DECRYPT_MODE, kek, Arrays.copyOf(wrapped, NONCE_BYTES),
                wrapAad(keyId, purpose), Arrays.copyOfRange(wrapped, NONCE_BYTES, wrapped.length)));
        } catch (GeneralSecurityException e) {
            return Optional.empty();
        }
    }

    /** A planned rotation's re-wrap: the same key, now under the active capture key; the content is never decrypted. */
    public Optional<Wrapped> rewrap(String keyId, byte[] wrapped, String purpose) {
        Optional<byte[]> key = unwrap(keyId, wrapped, purpose);
        if (key.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(wrap(key.get(), purpose));
        } finally {
            Arrays.fill(key.get(), (byte) 0);
        }
    }

    /**
     * The keyed content address of a chunk under the active capture key: HMAC-SHA256 under a key derived from it, hex.
     * After a rotation new chunks get new addresses (no deduplication across keys).
     */
    public String address(byte[] data, int off, int len) {
        String id = activeId;
        SecretKeySpec kek = id == null ? null : keys.get(id);
        if (kek == null) {
            throw new IllegalStateException("no active capture key");
        }
        byte[] label = "rwsafe-capture-address-v1".getBytes(StandardCharsets.US_ASCII);
        byte[] material = kek.getEncoded();
        byte[] derived = hmac(material, label, 0, label.length);
        Arrays.fill(material, (byte) 0);
        try {
            return java.util.HexFormat.of().formatHex(hmac(derived, data, off, len));
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    static byte[] hmac(byte[] key, byte[] data, int off, int len) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(data, off, len);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /** AES-256-GCM with a 12-byte nonce and a 128-bit tag. */
    static byte[] gcm(int mode, SecretKeySpec key, byte[] nonce, byte[] aad, byte[] input)
        throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, key, new GCMParameterSpec(TAG_BITS, nonce));
        c.updateAAD(aad);
        return c.doFinal(input);
    }

    private static byte[] wrapAad(String keyId, String purpose) {
        return ("rwsafe-capture-key|" + keyId + "|" + purpose).getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] random(int n) {
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
