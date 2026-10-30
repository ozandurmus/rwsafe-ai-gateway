package io.rwsafe.control.capture;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Envelope encryption under the capture key (AGENTS.md 4.13): sealed, bound to its record, shredded by rotation. */
class CaptureKeyringTest {

    @TempDir
    Path dir;

    /** A capture key generated at runtime; nothing secret-shaped is committed (AGENTS.md 4.5). */
    static void writeKey(Path dir, String id) throws Exception {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        Files.writeString(dir.resolve(id + ".key"), Base64.getEncoder().encodeToString(key) + "\n");
    }

    @Test
    void sealsAndOpensBoundToTheRecord() throws Exception {
        writeKey(dir, "cap-2026a");
        CaptureKeyring ring = new CaptureKeyring(dir);
        assertTrue(ring.available());
        byte[] plain = "synthetic: customer [REDACTED:TCKN] asks about fees".getBytes(StandardCharsets.UTF_8);
        byte[] aad = CaptureSink.aad(UUID.randomUUID());
        CaptureKeyring.Sealed s = ring.seal(plain, aad);
        assertEquals("cap-2026a", s.keyId());
        assertEquals(60, s.wrappedKey().length);
        assertFalse(new String(s.ciphertext(), StandardCharsets.ISO_8859_1).contains("customer"));
        assertArrayEquals(plain, ring.open(s.keyId(), s.wrappedKey(), s.nonce(), s.ciphertext(), aad).orElseThrow());
        assertTrue(ring.open(s.keyId(), s.wrappedKey(), s.nonce(), s.ciphertext(), CaptureSink.aad(UUID.randomUUID()))
            .isEmpty(), "a ciphertext moved to another event does not open");
        byte[] tampered = s.ciphertext().clone();
        tampered[0] ^= 1;
        assertTrue(ring.open(s.keyId(), s.wrappedKey(), s.nonce(), tampered, aad).isEmpty());
        assertFalse(s.toString().contains("customer"));
    }

    @Test
    void rotationKeepsOldRecordsUntilTheOldKeyIsRemoved() throws Exception {
        writeKey(dir, "cap-2026a");
        CaptureKeyring ring = new CaptureKeyring(dir);
        byte[] aad = CaptureSink.aad(UUID.randomUUID());
        CaptureKeyring.Sealed old = ring.seal(new byte[] {1, 2, 3}, aad);

        writeKey(dir, "cap-2026b");
        Files.writeString(dir.resolve("active"), "cap-2026b\n");
        ring.reload();
        assertEquals("cap-2026b", ring.activeId().orElseThrow());
        assertEquals(Set.of("cap-2026a", "cap-2026b"), ring.ids());
        assertTrue(ring.open(old.keyId(), old.wrappedKey(), old.nonce(), old.ciphertext(), aad).isPresent());

        Files.delete(dir.resolve("cap-2026a.key"));
        ring.reload();
        assertFalse(ring.has("cap-2026a"));
        assertTrue(ring.open(old.keyId(), old.wrappedKey(), old.nonce(), old.ciphertext(), aad).isEmpty(),
            "crypto-shredded");
    }

    @Test
    void anUnusableSecretLeavesCaptureUnavailable() throws Exception {
        assertFalse(new CaptureKeyring(dir.resolve("absent")).available());
        assertFalse(new CaptureKeyring(dir).available(), "an empty directory");
        Files.writeString(dir.resolve("short.key"), Base64.getEncoder().encodeToString(new byte[16]));
        assertFalse(new CaptureKeyring(dir).available(), "a key that is not 32 bytes");
        writeKey(dir, "cap-a");
        writeKey(dir, "cap-b");
        CaptureKeyring two = new CaptureKeyring(dir);
        assertFalse(two.available(), "two keys and no active file");
        assertThrows(IllegalStateException.class, () -> two.seal(new byte[1], new byte[1]));
        Files.writeString(dir.resolve("active"), "cap-c");
        assertFalse(new CaptureKeyring(dir).available(), "the active key is not mounted");
        Files.writeString(dir.resolve("active"), "cap-b");
        assertTrue(new CaptureKeyring(dir).available());
    }
}
