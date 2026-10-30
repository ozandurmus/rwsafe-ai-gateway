package io.rwsafe.policy;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * Verifies the Ed25519 signature the control plane puts on a snapshot body (POLICY_SNAPSHOT_CONTRACT.md). Holds up to a
 * few public keys by key id, so a key can rotate without a gap.
 */
public final class SnapshotVerifier {

    private static final String PREFIX = "ed25519:";

    private final Map<String, PublicKey> keys;

    public SnapshotVerifier(Map<String, PublicKey> keys) {
        this.keys = Map.copyOf(keys);
    }

    /** X.509 SubjectPublicKeyInfo in PEM ("-----BEGIN PUBLIC KEY-----"). */
    public static PublicKey publicKeyFromPem(String pem) throws GeneralSecurityException {
        String b64 = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
        StringBuilder clean = new StringBuilder();
        for (char c : b64.toCharArray()) {
            if (!Character.isWhitespace(c)) {
                clean.append(c);
            }
        }
        byte[] der = Base64.getDecoder().decode(clean.toString());
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
    }

    /** Throws {@link SnapshotCodec.Rejected} with UNKNOWN_KEY or BAD_SIGNATURE. */
    public void verify(byte[] body, String keyId, String signatureHeader) throws SnapshotCodec.Rejected {
        PublicKey key = keyId == null ? null : keys.get(keyId);
        if (key == null) {
            throw new SnapshotCodec.Rejected("UNKNOWN_KEY");
        }
        if (signatureHeader == null || !signatureHeader.startsWith(PREFIX)) {
            throw new SnapshotCodec.Rejected("BAD_SIGNATURE");
        }
        try {
            byte[] sig = Base64.getDecoder().decode(signatureHeader.substring(PREFIX.length())
                .getBytes(StandardCharsets.US_ASCII));
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(key);
            v.update(body);
            if (!v.verify(sig)) {
                throw new SnapshotCodec.Rejected("BAD_SIGNATURE");
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new SnapshotCodec.Rejected("BAD_SIGNATURE");
        }
    }
}
