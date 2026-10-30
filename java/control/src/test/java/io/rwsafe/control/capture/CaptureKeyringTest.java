package io.rwsafe.control.capture;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The capture key ring (AGENTS.md 4.13): wrapping bound to the key id and purpose, keyed addresses, planned re-wrap
 * without opening content, emergency shredding by the Secret's {@code shredded} list, and an unusable Secret refused.
 */
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
    void wrapsBoundToKeyAndPurpose() throws Exception {
        writeKey(dir, "cap-2026a");
        CaptureKeyring ring = new CaptureKeyring(dir);
        assertTrue(ring.available());
        byte[] dek = CaptureKeyring.newKey();
        CaptureKeyring.Wrapped w = ring.wrap(dek, "chunk|aa");
        assertEquals("cap-2026a", w.keyId());
        assertEquals(CaptureKeyring.WRAPPED_BYTES, w.wrapped().length);
        assertArrayEquals(dek, ring.unwrap("cap-2026a", w.wrapped(), "chunk|aa").orElseThrow());
        assertTrue(ring.unwrap("cap-2026a", w.wrapped(), "chunk|bb").isEmpty(), "another purpose does not open");
        byte[] tampered = w.wrapped().clone();
        tampered[20] ^= 1;
        assertTrue(ring.unwrap("cap-2026a", tampered, "chunk|aa").isEmpty());
        assertFalse(w.toString().contains(new String(dek, StandardCharsets.ISO_8859_1)));
        byte[] text = "synthetic chunk".getBytes(StandardCharsets.UTF_8);
        assertEquals(ring.address(text, 0, text.length), ring.address(text, 0, text.length));
        assertEquals(64, ring.address(text, 0, text.length).length());
    }

    @Test
    void plannedRotationRewrapsAndTheShreddedListDestroysAKey() throws Exception {
        writeKey(dir, "cap-2026a");
        CaptureKeyring ring = new CaptureKeyring(dir);
        byte[] dek = CaptureKeyring.newKey();
        CaptureKeyring.Wrapped old = ring.wrap(dek, "record|x");
        byte[] text = "synthetic chunk".getBytes(StandardCharsets.UTF_8);
        String oldAddress = ring.address(text, 0, text.length);

        writeKey(dir, "cap-2026b");
        Files.writeString(dir.resolve("active"), "cap-2026b\n");
        ring.reload();
        assertEquals("cap-2026b", ring.activeId().orElseThrow());
        assertNotEquals(oldAddress, ring.address(text, 0, text.length), "addresses are keyed per capture key");
        CaptureKeyring.Wrapped moved = ring.rewrap(old.keyId(), old.wrapped(), "record|x").orElseThrow();
        assertEquals("cap-2026b", moved.keyId());
        assertArrayEquals(dek, ring.unwrap("cap-2026b", moved.wrapped(), "record|x").orElseThrow());

        Files.writeString(dir.resolve("shredded"), "cap-2026a\n");
        ring.reload();
        assertEquals(Set.of("cap-2026a"), ring.shredded());
        assertFalse(ring.has("cap-2026a"), "a listed key is never used, even while its file is mounted");
        assertTrue(ring.unwrap(old.keyId(), old.wrapped(), "record|x").isEmpty());
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
        assertThrows(IllegalStateException.class, () -> two.wrap(new byte[32], "x"));
        Files.writeString(dir.resolve("active"), "cap-c");
        assertFalse(new CaptureKeyring(dir).available(), "the active key is not mounted");
        Files.writeString(dir.resolve("active"), "cap-b");
        assertTrue(new CaptureKeyring(dir).available());
        Files.writeString(dir.resolve("shredded"), "cap-b");
        assertFalse(new CaptureKeyring(dir).available(), "the active key is listed as shredded");
    }
}
