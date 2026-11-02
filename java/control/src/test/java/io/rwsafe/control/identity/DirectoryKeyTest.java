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

    private static final java.util.List<String> URLS = java.util.List.of("ldaps://synthetic-dc1.example.test:636");
    private static final String BIND_DN = "cn=synthetic-service,dc=example,dc=test";
    private static final byte[] CTX = DirectoryKey.context(3, "ldaps", BIND_DN, URLS, null);

    @TempDir
    Path dir;

    /**
     * PR 50 review D-01: the associated data binds a sealed password to its version, TLS mode, bind DN, URLs and CA
     * bundle; under any other of them it does not open.
     */
    @Test
    void aSealedPasswordOpensOnlyForTheSettingsItWasSealedFor() throws Exception {
        DirectoryKey key = new DirectoryKey(key("bound", 32));
        byte[] sealed = key.seal(password(), CTX);
        java.util.List<byte[]> others = java.util.List.of(
            DirectoryKey.context(4, "ldaps", BIND_DN, URLS, null),
            DirectoryKey.context(3, "starttls", BIND_DN, URLS, null),
            DirectoryKey.context(3, "ldaps", "cn=synthetic-other,dc=example,dc=test", URLS, null),
            DirectoryKey.context(3, "ldaps", BIND_DN, java.util.List.of("ldaps://synthetic-elsewhere.example.test:636"),
                null),
            DirectoryKey.context(3, "ldaps", BIND_DN, URLS, "-----BEGIN CERTIFICATE-----\nAAAA\n"),
            // Field boundaries are encoded: moving text between fields is another context.
            DirectoryKey.context(3, "ldaps", BIND_DN + ";", URLS, null));
        for (byte[] other : others) {
            assertEquals("BIND_PASSWORD_UNREADABLE", assertThrows(DirectoryKey.Unavailable.class,
                () -> key.open(sealed, other)).reason());
        }
        assertEquals(DirectoryKey.context(3, "ldaps", BIND_DN, URLS, null).length, CTX.length);
        key.open(sealed, DirectoryKey.context(3, "ldaps", BIND_DN, URLS, null));
    }

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
        byte[] sealed = key.seal(password, CTX);
        assertEquals(DirectoryKey.FORMAT, sealed[0]);
        assertArrayEquals(password, key.open(sealed, CTX));
        // A fresh nonce every time; the plaintext is nowhere in the sealed bytes.
        assertFalse(java.util.Arrays.equals(sealed, key.seal(password, CTX)));
        assertFalse(new String(sealed, StandardCharsets.ISO_8859_1).contains(new String(password, 0, 12)));

        DirectoryKey other = new DirectoryKey(key("other", 32));
        assertEquals("BIND_PASSWORD_UNREADABLE", assertThrows(DirectoryKey.Unavailable.class,
            () -> other.open(sealed, CTX)).reason());
        byte[] tampered = sealed.clone();
        tampered[tampered.length - 1] ^= 1;
        assertEquals("BIND_PASSWORD_UNREADABLE", assertThrows(DirectoryKey.Unavailable.class,
            () -> key.open(tampered, CTX)).reason());
        byte[] wrongFormat = sealed.clone();
        wrongFormat[0] = 2;
        assertEquals("BIND_PASSWORD_UNREADABLE", assertThrows(DirectoryKey.Unavailable.class,
            () -> key.open(wrongFormat, CTX)).reason());
    }

    @Test
    void withoutAUsableKeyNothingIsSealedOrOpened() throws Exception {
        DirectoryKey missing = new DirectoryKey(dir.resolve("absent"));
        assertEquals(DirectoryKey.State.MISSING, missing.state());
        assertEquals("DIRECTORY_KEY_MISSING", assertThrows(DirectoryKey.Unavailable.class,
            () -> missing.seal(password(), CTX)).reason());
        assertEquals(DirectoryKey.State.MISSING, new DirectoryKey(null).state());

        DirectoryKey shortKey = new DirectoryKey(key("short", 16));
        assertEquals(DirectoryKey.State.INVALID, shortKey.state());
        assertEquals("DIRECTORY_KEY_INVALID", assertThrows(DirectoryKey.Unavailable.class,
            () -> shortKey.seal(password(), CTX)).reason());
        byte[] sealed = new DirectoryKey(key("good", 32)).seal(password(), CTX);
        assertEquals("DIRECTORY_KEY_INVALID", assertThrows(DirectoryKey.Unavailable.class,
            () -> shortKey.open(sealed, CTX)).reason());
    }
}
