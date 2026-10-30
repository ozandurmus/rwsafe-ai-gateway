package io.rwsafe.dataplane.server;

/**
 * Limits of the ICAP engine (ICAP spec §3). Defaults are the spec's values; tests shrink them.
 *
 * @param maxReqmodBody         REQMOD body cap; above it the transaction is {@code UNINSPECTABLE(OVERSIZE)}
 * @param maxEncapsulatedHeads  combined size of the encapsulated HTTP heads
 * @param windowBytes           RESPMOD sliding window
 * @param windowOverlap         bytes of the previous window re-inspected with the next
 * @param bodyTimeoutMillis     REQMOD body-receive timeout
 * @param streamIdleSeconds     inter-chunk idle timeout while a body is being received
 * @param connectionIdleSeconds idle keep-alive connection timeout
 */
public record EngineConfig(int maxReqmodBody, int maxEncapsulatedHeads, int windowBytes, int windowOverlap,
                           long bodyTimeoutMillis, int streamIdleSeconds, int connectionIdleSeconds) {

    public static EngineConfig defaults() {
        return new EngineConfig(4 * 1024 * 1024, 128 * 1024, 16 * 1024, 2 * 1024, 10_000, 30, 300);
    }
}
