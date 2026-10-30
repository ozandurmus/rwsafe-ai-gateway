package io.rwsafe.persistence;

import java.time.Instant;
import java.util.UUID;

/**
 * One stored C3 record as the database holds it: ciphertext and a wrapped data key, never plaintext (ADR-009 C3,
 * AGENTS.md 4.13). The control plane seals and opens it; this module never sees a key.
 *
 * @param wrappedKey nonce (12) || AES-GCM(capture key, data key) || tag (16), 60 bytes
 * @param plainBytes the UTF-8 size of the stored redacted text
 */
public record SealedCapture(UUID eventId, Instant capturedAt, Instant expiresAt, String userPseudonym, String keyId,
                            byte[] wrappedKey, byte[] nonce, byte[] ciphertext, int plainBytes, boolean truncated,
                            String maskRuleSet, boolean legalHold) {

    /** Sizes and ids only. */
    @Override
    public String toString() {
        return "SealedCapture[" + eventId + ", key " + keyId + ", " + plainBytes + " bytes]";
    }
}
