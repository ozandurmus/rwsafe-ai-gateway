package io.rwsafe.dataplane.server;

import java.util.List;

/**
 * Limits of the ICAP engine (ICAP spec §3, §7). Defaults are the spec's values; tests shrink them with the {@code with}
 * methods.
 *
 * @param maxReqmodBody          REQMOD body cap; above it the transaction is {@code UNINSPECTABLE(OVERSIZE)}
 * @param maxEncapsulatedHeads   combined size of the encapsulated HTTP heads
 * @param windowBytes            RESPMOD sliding window
 * @param windowOverlap          normalised characters of the previous window re-inspected with the next
 * @param bodyTimeoutMillis      REQMOD transaction deadline from its first byte (head and body)
 * @param respmodTimeoutMillis   RESPMOD transaction deadline (streams, ICAP spec §6)
 * @param streamIdleSeconds      inter-chunk idle timeout while a body is being received
 * @param connectionIdleSeconds  idle keep-alive connection timeout
 * @param maxInflight            transactions in flight per engine; beyond it new ones get 503
 * @param perIdentityInflight    transactions in flight per claimed user (fallback: client address)
 * @param perSharedAddress       transactions in flight per shared address (VDI, terminal servers)
 * @param bodyBudgetBytes        pod-wide cap on captured REQMOD body bytes held at once (PLAT-F1)
 * @param drainServeMillis       how long a draining engine keeps serving with Connection: close
 * @param sharedAddressPrefixes  client-address prefixes that are shared by many users (runtime configuration)
 * @param groupClaimEncoding     how the proxy encodes {@code X-Authenticated-Groups}; {@code DISABLED} by default
 * @param captureMaxBytes        redacted capture (Q-4 b): 0 (the default) is off; otherwise the most bytes of the
 *                               rewritten body a verdict event carries, at most {@link #MAX_CAPTURE_BYTES}
 */
public record EngineConfig(int maxReqmodBody, int maxEncapsulatedHeads, int windowBytes, int windowOverlap,
                           long bodyTimeoutMillis, long respmodTimeoutMillis, int streamIdleSeconds,
                           int connectionIdleSeconds, int maxInflight, int perIdentityInflight, int perSharedAddress,
                           long bodyBudgetBytes, long drainServeMillis, List<String> sharedAddressPrefixes,
                           GroupClaimEncoding groupClaimEncoding, int captureMaxBytes) {

    /** The capture bound's ceiling: one escaped capture stays far below a posted array's size (VerdictEventJson). */
    public static final int MAX_CAPTURE_BYTES = 64 * 1024;
    /** The bound {@code RWSAFE_CAPTURE_MODE=redacted} uses unless {@code RWSAFE_CAPTURE_MAX_BYTES} says otherwise. */
    public static final int DEFAULT_CAPTURE_BYTES = 32 * 1024;

    /**
     * {@code RWSAFE_GROUP_CLAIM_ENCODING} (PR 20 review D-01, Q-1): the engine never guesses the header's encoding per
     * value. {@code plain}: the header value is the comma-separated group list, its octets read as UTF-8. {@code base64}:
     * the whole header value is standard base64 (RFC 4648 section 4 alphabet, padding required) of that same list in
     * UTF-8. Unset or any other value: group claims are disabled and every transaction takes the strictest policy.
     */
    public enum GroupClaimEncoding {
        DISABLED, PLAIN, BASE64;

        /** Exactly {@code plain} or {@code base64}; anything else, including null, disables group claims. */
        public static GroupClaimEncoding fromSetting(String value) {
            if ("plain".equals(value)) {
                return PLAIN;
            }
            return "base64".equals(value) ? BASE64 : DISABLED;
        }
    }

    public EngineConfig {
        sharedAddressPrefixes = List.copyOf(sharedAddressPrefixes);
        if (groupClaimEncoding == null) {
            groupClaimEncoding = GroupClaimEncoding.DISABLED;
        }
        if (captureMaxBytes < 0 || captureMaxBytes > MAX_CAPTURE_BYTES) {
            throw new IllegalArgumentException("captureMaxBytes is between 0 (off) and " + MAX_CAPTURE_BYTES);
        }
    }

    public static EngineConfig defaults() {
        return new EngineConfig(4 * 1024 * 1024, 128 * 1024, 16 * 1024, 2 * 1024, 10_000, 300_000, 30, 300,
            1000, 32, 256, 256L * 1024 * 1024, 15_000, List.of(), GroupClaimEncoding.DISABLED, 0);
    }

    /** True when verdict events may carry redacted content. */
    public boolean captureRedacted() {
        return captureMaxBytes > 0;
    }

    /**
     * {@code RWSAFE_CAPTURE_MODE}: exactly {@code redacted} turns capture on with {@code maxBytes} (or the default when
     * null); unset or anything else keeps it off (metadata and verdicts only).
     */
    public static int captureBytesFromSetting(String mode, String maxBytes) {
        if (!"redacted".equals(mode)) {
            return 0;
        }
        if (maxBytes == null || maxBytes.isBlank()) {
            return DEFAULT_CAPTURE_BYTES;
        }
        int n = Integer.parseInt(maxBytes.strip());
        if (n < 1 || n > MAX_CAPTURE_BYTES) {
            throw new IllegalArgumentException("RWSAFE_CAPTURE_MAX_BYTES is between 1 and " + MAX_CAPTURE_BYTES);
        }
        return n;
    }

    public EngineConfig withCapture(int captureMaxBytes) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes, groupClaimEncoding,
            captureMaxBytes);
    }

    public EngineConfig withBodyLimits(int maxReqmodBody, long bodyBudgetBytes) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes, groupClaimEncoding, captureMaxBytes);
    }

    public EngineConfig withWindow(int windowBytes, int windowOverlap) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes, groupClaimEncoding, captureMaxBytes);
    }

    public EngineConfig withTimeouts(long bodyTimeoutMillis, long respmodTimeoutMillis) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes, groupClaimEncoding, captureMaxBytes);
    }

    public EngineConfig withAdmission(int maxInflight, int perIdentityInflight, int perSharedAddress,
                                      List<String> sharedAddressPrefixes) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes, groupClaimEncoding, captureMaxBytes);
    }

    public EngineConfig withDrainServeMillis(long drainServeMillis) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes, groupClaimEncoding, captureMaxBytes);
    }

    public EngineConfig withGroupClaimEncoding(GroupClaimEncoding groupClaimEncoding) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes, groupClaimEncoding, captureMaxBytes);
    }

    long drainServeNanos() {
        return drainServeMillis * 1_000_000L;
    }
}
