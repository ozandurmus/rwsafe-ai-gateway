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
 */
public record EngineConfig(int maxReqmodBody, int maxEncapsulatedHeads, int windowBytes, int windowOverlap,
                           long bodyTimeoutMillis, long respmodTimeoutMillis, int streamIdleSeconds,
                           int connectionIdleSeconds, int maxInflight, int perIdentityInflight, int perSharedAddress,
                           long bodyBudgetBytes, long drainServeMillis, List<String> sharedAddressPrefixes) {

    public EngineConfig {
        sharedAddressPrefixes = List.copyOf(sharedAddressPrefixes);
    }

    public static EngineConfig defaults() {
        return new EngineConfig(4 * 1024 * 1024, 128 * 1024, 16 * 1024, 2 * 1024, 10_000, 300_000, 30, 300,
            1000, 32, 256, 256L * 1024 * 1024, 15_000, List.of());
    }

    public EngineConfig withBodyLimits(int maxReqmodBody, long bodyBudgetBytes) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes);
    }

    public EngineConfig withWindow(int windowBytes, int windowOverlap) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes);
    }

    public EngineConfig withTimeouts(long bodyTimeoutMillis, long respmodTimeoutMillis) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes);
    }

    public EngineConfig withAdmission(int maxInflight, int perIdentityInflight, int perSharedAddress,
                                      List<String> sharedAddressPrefixes) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes);
    }

    public EngineConfig withDrainServeMillis(long drainServeMillis) {
        return new EngineConfig(maxReqmodBody, maxEncapsulatedHeads, windowBytes, windowOverlap, bodyTimeoutMillis,
            respmodTimeoutMillis, streamIdleSeconds, connectionIdleSeconds, maxInflight, perIdentityInflight,
            perSharedAddress, bodyBudgetBytes, drainServeMillis, sharedAddressPrefixes);
    }

    long drainServeNanos() {
        return drainServeMillis * 1_000_000L;
    }
}
