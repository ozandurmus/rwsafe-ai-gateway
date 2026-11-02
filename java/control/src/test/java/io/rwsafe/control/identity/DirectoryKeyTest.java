package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The directory key: AES-256-GCM round trip, fail closed without a usable key, and no plaintext in the sealed form. */
class DirectoryKeyTest {

    @TempDir
    Path dir;

    private Path key(String name, int bytes) throws Exception {
        byte[] b = new byte[bytes];
        new SecureRandom().nextBytes(b);
        return Files.write(dir.resolve(name), b);
    }

    private static char[] password() {
        byte[] b = new byte[12];
        new SecureRandom().nextBytes(b);
        return ("Synthetic-" + HexFormat.of().formatHex(b) + "-İş").toCharArray();
    }

    @Test
    void aSealedPasswordOpensUnderTheSameKeyOnly() throws Exception {
        DirectoryKey key = new DirectoryKey(key("key", 32));
        assertEquals(DirectoryKey.State.AVAILABLE, key.state());
        char[] password = password();
        byte[] sealed = key.seal(password);
        assertEquals(DirectoryKey.FORMAT, sealed[0]);
        assertArrayEquals(password, key.open(sealed));
        // A fresh nonce every time; the plaintext is nowhere in the sealed bytes.
        assertFalse(java.util.Arrays.equals(sealed, key.seal(password)));
        assertFalse(new String(sealed, StandardCharsets.ISO_8859_1).contains(new String(password, 0, 12)));

        DirectoryKey other = new DirectoryKey(key("other", 32));
        assertEquals("BIND_PASSWORD_UNREADABLE", assertThrows(DirectoryKey.Unavailable.class,
            () -> other.open(sealed)).reason());
        byte[] tampered = sealed.clone();
        tampered[tampered.length - 1] ^= 1;
        assertEquals("BIND_PASSWORD_UNREADABLE", assertThrows(DirectoryKey.Unavailable.class,
            () -> key.open(tampered)).reason());
        byte[] wrongFormat = sealed.clone();
        wrongFormat[0] = 2;
        assertEquals("BIND_PASSWORD_UNREADABLE", assertThrows(DirectoryKey.Unavailable.class,
            () -> key.open(wrongFormat)).reason());
    }

    @Test
    void withoutAUsableKeyNothingIsSealedOrOpened() throws Exception {
        DirectoryKey missing = new DirectoryKey(dir.resolve("absent"));
        assertEquals(DirectoryKey.State.MISSING, missing.state());
        assertEquals("DIRECTORY_KEY_MISSING", assertThrows(DirectoryKey.Unavailable.class,
            () -> missing.seal(password())).reason());
        assertEquals(DirectoryKey.State.MISSING, new DirectoryKey(null).state());

        DirectoryKey shortKey = new DirectoryKey(key("short", 16));
        assertEquals(DirectoryKey.State.INVALID, shortKey.state());
        assertEquals("DIRECTORY_KEY_INVALID", assertThrows(DirectoryKey.Unavailable.class,
            () -> shortKey.seal(password())).reason());
        byte[] sealed = new DirectoryKey(key("good", 32)).seal(password());
        assertEquals("DIRECTORY_KEY_INVALID", assertThrows(DirectoryKey.Unavailable.class,
            () -> shortKey.open(sealed)).reason());
    }
}
