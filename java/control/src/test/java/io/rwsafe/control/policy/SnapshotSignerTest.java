package io.rwsafe.control.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.support.ControlTestEnvironment;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Ed25519 through the JDK, keys generated at runtime; nothing of a key is committed. */
class SnapshotSignerTest {

    @TempDir
    Path dir;

    private static ControlProperties properties(Path keyFile, String keyId) {
        return new ControlProperties(null, null, null, null,
            new ControlProperties.Policy(null, keyFile, keyId, null, null), null, null, null);
    }

    @Test
    void signsTheExactBytesAndVerifiesWithThePublicKey() throws Exception {
        KeyPair keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Path file = dir.resolve("snapshot-2026a.pem.txt");
        Files.writeString(file, ControlTestEnvironment.pem(keys.getPrivate().getEncoded()));
        SnapshotSigner signer = new SnapshotSigner(properties(file, ""));
        assertTrue(signer.available());
        assertEquals("snapshot-2026a.pem", signer.keyId(), "the file name without its extension");
        byte[] doc = "{\"format\":1}".getBytes(StandardCharsets.UTF_8);
        String signature = signer.sign(doc);
        assertTrue(signature.startsWith("ed25519:"));
        assertEquals(signature, signer.sign(doc), "Ed25519 is deterministic");
        Signature verify = Signature.getInstance("Ed25519");
        verify.initVerify(keys.getPublic());
        verify.update(doc);
        assertTrue(verify.verify(Base64.getDecoder().decode(signature.substring("ed25519:".length()))));
    }

    @Test
    void aMissingOrForeignKeyLeavesTheSignerUnavailable() throws Exception {
        SnapshotSigner missing = new SnapshotSigner(properties(dir.resolve("absent"), "k1"));
        assertFalse(missing.available());
        assertTrue(missing.unavailableReason().contains("missing"));
        assertThrows(IllegalStateException.class, () -> missing.sign(new byte[1]));

        KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Path foreign = dir.resolve("rsa");
        Files.writeString(foreign, ControlTestEnvironment.pem(rsa.getPrivate().getEncoded()));
        SnapshotSigner wrongAlgorithm = new SnapshotSigner(properties(foreign, "k1"));
        assertFalse(wrongAlgorithm.available());
        assertTrue(wrongAlgorithm.unavailableReason().contains("Ed25519"));

        assertNull(SnapshotSigner.keyId("bad id/with slash", null));
        assertEquals("k1", SnapshotSigner.keyId("k1", foreign));
    }
}
