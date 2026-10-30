package io.rwsafe.control.privacy;

import io.rwsafe.control.config.ControlProperties;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * rwsafe's own privacy HMAC key (MASKING_AND_PRIVACY B3: {@code rwsafe-privacy-hmac-key}, at least 32 bytes, never
 * neXus's) and the estate dictionary, both read once from mounted files at start. A missing or short key, or a missing
 * dictionary, leaves masking unavailable: ingestion refuses to store and masked requests get 503 (fail closed).
 */
@Component
public class PrivacyKeys {

    static final int MIN_KEY_BYTES = 32;
    private static final Logger LOG = LoggerFactory.getLogger(PrivacyKeys.class);

    private final SecretKeySpec key;
    private final String keyId;
    private final List<String> estateTerms;

    @Autowired
    public PrivacyKeys(ControlProperties properties) {
        this(read(properties.privacy().hmacKeyFile()), readTerms(properties.privacy().estateDictionaryFile()));
    }

    PrivacyKeys(byte[] keyBytes, List<String> estateTerms) {
        if (keyBytes == null || keyBytes.length < MIN_KEY_BYTES) {
            this.key = null;
            this.keyId = null;
            LOG.warn("privacy HMAC key missing or shorter than {} bytes: ingestion and masked views are refused",
                MIN_KEY_BYTES);
        } else {
            this.key = new SecretKeySpec(keyBytes, "HmacSHA256");
            this.keyId = keyId(keyBytes);
        }
        this.estateTerms = estateTerms == null ? null : List.copyOf(estateTerms);
        if (estateTerms == null) {
            LOG.warn("estate dictionary missing: masked views are refused");
        }
    }

    /** True when pseudonyms can be computed (ingestion). */
    public boolean keyAvailable() {
        return key != null;
    }

    /** True when the masked role can be served: the key and the estate dictionary are both present. */
    public boolean maskingAvailable() {
        return key != null && estateTerms != null;
    }

    /** A short public identifier of the key (rotation detection), never the key. */
    public String keyId() {
        requireKey();
        return keyId;
    }

    /** Lower-case estate terms (layer 3). */
    public List<String> estateTerms() {
        if (estateTerms == null) {
            throw new MaskingUnavailableException("estate dictionary");
        }
        return estateTerms;
    }

    /** HMAC-SHA256 of {@code purpose || 0x00 || value}; the purpose separates the pseudonym kinds. */
    public byte[] hmac(String purpose, String value) {
        requireKey();
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            mac.update(purpose.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) 0);
            return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private void requireKey() {
        if (key == null) {
            throw new MaskingUnavailableException("privacy key");
        }
    }

    private static String keyId(byte[] keyBytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(keyBytes);
            return "k" + HexFormat.of().formatHex(digest, 0, 4);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static byte[] read(Path file) {
        if (file == null) {
            return null;
        }
        try {
            return Files.readAllBytes(file);
        } catch (IOException e) {
            return null;
        }
    }

    private static List<String> readTerms(Path file) {
        if (file == null) {
            return null;
        }
        try {
            List<String> terms = new ArrayList<>();
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                String term = line.strip();
                if (!term.isEmpty() && !term.startsWith("#")) {
                    terms.add(term.toLowerCase(Locale.ROOT));
                }
            }
            // Longest first, so a term that contains a shorter one is masked whole (PR 12 review D-01).
            terms.sort(java.util.Comparator.comparingInt(String::length).reversed());
            return terms;
        } catch (IOException e) {
            return null;
        }
    }
}
