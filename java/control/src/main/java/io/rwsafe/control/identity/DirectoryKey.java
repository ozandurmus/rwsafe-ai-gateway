package io.rwsafe.control.identity;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The directory bind password's own key (PO decision Q-47, decision 1.2): 32 random bytes in the product's Kubernetes
 * Secret {@code rwsafe-directory-key} (key {@code key}), mounted as a file, never the privacy or the capture key. The
 * password is sealed with AES-256-GCM: format byte {@code 0x01}, a random 12-byte nonce, the ciphertext and the 16-byte
 * tag. The associated data binds the ciphertext to the settings it was saved for (PR 50 review D-01): the version, the
 * TLS mode, the bind DN, the URLs and the CA bundle's digest ({@link #context}); a sealed value copied to other settings
 * does not open. The file is read at each use, so the key is never held longer than one seal or open.
 * Without a readable 32-byte key nothing is sealed or opened: there is no plaintext fallback (AGENTS.md 4.10).
 */
public final class DirectoryKey {

    /** Why the key cannot be used; {@code AVAILABLE} when it can. */
    public enum State { AVAILABLE, MISSING, INVALID }

    /** The key cannot be used, or a sealed value does not open under it. */
    public static final class Unavailable extends Exception {

        private static final long serialVersionUID = 1L;
        private final String reason;

        Unavailable(String reason, String message) {
            super(message);
            this.reason = reason;
        }

        /** {@code DIRECTORY_KEY_MISSING}, {@code DIRECTORY_KEY_INVALID} or {@code BIND_PASSWORD_UNREADABLE}. */
        public String reason() {
            return reason;
        }
    }

    static final byte FORMAT = 1;
    static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final String AAD_PREFIX = "rwsafe.directory.bind-password.v1";

    /**
     * The canonical associated data of one settings version: a fixed label, then each field as its UTF-8 byte length,
     * a colon, the bytes and a semicolon (so no two field lists encode alike): the version, the TLS mode, the bind DN,
     * the URLs in order, and the SHA-256 of the CA bundle (empty when none).
     */
    public static byte[] context(int version, String tlsMode, String bindDn, java.util.List<String> urls,
                                 String caPem) {
        StringBuilder b = new StringBuilder(AAD_PREFIX).append(';');
        field(b, Integer.toString(version));
        field(b, tlsMode);
        field(b, bindDn);
        field(b, Integer.toString(urls.size()));
        urls.forEach(u -> field(b, u));
        String digest = "";
        if (caPem != null) {
            try {
                digest = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(caPem.getBytes(StandardCharsets.UTF_8)));
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 is not available in this runtime", e);
            }
        }
        field(b, digest);
        return b.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void field(StringBuilder b, String value) {
        String v = value == null ? "" : value;
        b.append(v.getBytes(StandardCharsets.UTF_8).length).append(':').append(v).append(';');
    }
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path file;

    public DirectoryKey(Path file) {
        this.file = file;
    }

    public State state() {
        try {
            Arrays.fill(read(), (byte) 0);
            return State.AVAILABLE;
        } catch (Unavailable e) {
            return e.reason().equals("DIRECTORY_KEY_MISSING") ? State.MISSING : State.INVALID;
        }
    }

    /** Seals {@code password} (UTF-8); the caller clears its own copy. */
    public byte[] seal(char[] password, byte[] context) throws Unavailable {
        byte[] key = read();
        byte[] plain = utf8(password);
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            c.updateAAD(context);
            byte[] sealed = c.doFinal(plain);
            return ByteBuffer.allocate(1 + NONCE_BYTES + sealed.length).put(FORMAT).put(nonce).put(sealed).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM is not available in this runtime", e);
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(plain, (byte) 0);
        }
    }

    /** Opens a sealed password; {@code BIND_PASSWORD_UNREADABLE} when it was sealed under another key or altered. */
    public char[] open(byte[] sealed, byte[] context) throws Unavailable {
        byte[] key = read();
        try {
            if (sealed == null || sealed.length < 1 + NONCE_BYTES + TAG_BITS / 8 + 1 || sealed[0] != FORMAT) {
                throw new Unavailable("BIND_PASSWORD_UNREADABLE", "The stored bind password has an unknown format.");
            }
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, sealed, 1, NONCE_BYTES));
            c.updateAAD(context);
            byte[] plain = c.doFinal(sealed, 1 + NONCE_BYTES, sealed.length - 1 - NONCE_BYTES);
            try {
                CharBuffer chars = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(plain));
                char[] out = new char[chars.remaining()];
                chars.get(out);
                Arrays.fill(chars.array(), '\0');
                return out;
            } finally {
                Arrays.fill(plain, (byte) 0);
            }
        } catch (javax.crypto.AEADBadTagException e) {
            throw new Unavailable("BIND_PASSWORD_UNREADABLE",
                "The stored bind password does not open under the current directory key and settings (was the key "
                    + "replaced?).");
        } catch (java.nio.charset.CharacterCodingException e) {
            throw new Unavailable("BIND_PASSWORD_UNREADABLE", "The stored bind password is not text.");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM is not available in this runtime", e);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private byte[] read() throws Unavailable {
        if (file == null || !Files.isRegularFile(file)) {
            throw new Unavailable("DIRECTORY_KEY_MISSING", "The directory key Secret is not mounted.");
        }
        byte[] key;
        try {
            key = Files.readAllBytes(file);
        } catch (IOException | RuntimeException e) {
            throw new Unavailable("DIRECTORY_KEY_MISSING", "The directory key file is unreadable.");
        }
        if (key.length != KEY_BYTES) {
            Arrays.fill(key, (byte) 0);
            throw new Unavailable("DIRECTORY_KEY_INVALID", "The directory key is not 32 bytes.");
        }
        return key;
    }

    private static byte[] utf8(char[] chars) {
        ByteBuffer b = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] out = new byte[b.remaining()];
        b.get(out);
        if (b.hasArray()) {
            Arrays.fill(b.array(), (byte) 0);
        }
        return out;
    }
}
