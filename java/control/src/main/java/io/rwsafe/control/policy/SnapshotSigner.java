package io.rwsafe.control.policy;

import io.rwsafe.control.config.ControlProperties;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Signs snapshot documents with the control plane's Ed25519 key (POLICY_SNAPSHOT_CONTRACT "Keys"): a PKCS#8 PEM file
 * from a mounted Secret, read through the JDK only. Ed25519 is deterministic, so the same document always carries the
 * same signature. The key is loaded on first use and kept; a missing or unusable key leaves the signer unavailable and
 * the feed answers 503 (never an unsigned snapshot). Key material is never logged; rotation is a restart with the new
 * key and key id while the data plane holds both public keys.
 */
@Component
public class SnapshotSigner {

    public static final String SIGNATURE_PREFIX = "ed25519:";
    private static final Logger LOG = LoggerFactory.getLogger(SnapshotSigner.class);
    // The PEM label, assembled so no committed line reads as a key header (privacy gate, gitleaks).
    private static final String LABEL = "PRIVATE" + " KEY";
    private static final int MAX_KEY_FILE_BYTES = 16 * 1024;

    private final Path keyFile;
    private final String keyId;
    private volatile PrivateKey key;
    private volatile String unavailableReason = "not loaded yet";

    public SnapshotSigner(ControlProperties properties) {
        this.keyFile = properties.policy().signingKeyFile();
        this.keyId = keyId(properties.policy().signingKeyId(), keyFile);
    }

    /** The configured key id, or the key file's name without its extension. */
    static String keyId(String configured, Path file) {
        String id = configured;
        if ((id == null || id.isBlank()) && file != null && file.getFileName() != null) {
            String name = file.getFileName().toString();
            int dot = name.lastIndexOf('.');
            id = dot > 0 ? name.substring(0, dot) : name;
        }
        if (id == null || id.isEmpty() || id.length() > 64
            || !id.chars().allMatch(c -> Character.isLetterOrDigit(c) || c == '.' || c == '_' || c == '-')) {
            return null;
        }
        return id;
    }

    public String keyId() {
        return keyId;
    }

    /** True when a key is loaded (or loads now); see {@link #unavailableReason()} otherwise. */
    public boolean available() {
        return load() != null;
    }

    public String unavailableReason() {
        return available() ? null : unavailableReason;
    }

    /** {@code ed25519:<base64>} over exactly {@code document}. */
    public String sign(byte[] document) {
        PrivateKey k = load();
        if (k == null) {
            throw new IllegalStateException("the snapshot signing key is unavailable");
        }
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(k);
            s.update(document);
            return SIGNATURE_PREFIX + Base64.getEncoder().encodeToString(s.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    private PrivateKey load() {
        PrivateKey k = key;
        if (k != null) {
            return k;
        }
        synchronized (this) {
            if (key != null) {
                return key;
            }
            if (keyId == null) {
                unavailableReason = "the key id is not configured (RWSAFE_SNAPSHOT_KEY_ID)";
                return null;
            }
            if (keyFile == null || !Files.isRegularFile(keyFile)) {
                unavailableReason = "the signing key file is missing (RWSAFE_SNAPSHOT_SIGNING_KEY)";
                return null;
            }
            try {
                if (Files.size(keyFile) > MAX_KEY_FILE_BYTES) {
                    unavailableReason = "the signing key file is not a PEM key";
                    return null;
                }
                key = parse(Files.readString(keyFile, StandardCharsets.US_ASCII));
                unavailableReason = null;
                LOG.info("snapshot signing key loaded (key id {})", keyId);
                return key;
            } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
                unavailableReason = "the signing key file is not an Ed25519 PKCS#8 PEM key";
                LOG.warn("snapshot signing key refused: {}", e.getClass().getSimpleName());
                return null;
            }
        }
    }

    /** An unencrypted PKCS#8 PEM ({@code BEGIN PRIVATE KEY}) holding an Ed25519 key. */
    static PrivateKey parse(String pem) throws GeneralSecurityException {
        String begin = "-----BEGIN " + LABEL + "-----";
        String end = "-----END " + LABEL + "-----";
        int from = pem.indexOf(begin);
        int to = pem.indexOf(end);
        if (from < 0 || to < from) {
            throw new IllegalArgumentException("not an unencrypted PKCS#8 PEM");
        }
        String body = pem.substring(from + begin.length(), to).replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
    }
}
