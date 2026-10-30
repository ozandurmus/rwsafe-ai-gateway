package io.rwsafe.dataplane.controlplane;

import io.rwsafe.dataplane.server.IcapEngine;
import io.rwsafe.policy.PolicySnapshot;
import io.rwsafe.policy.SnapshotCodec;
import io.rwsafe.policy.SnapshotVerifier;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

/**
 * Pulls the signed policy snapshot from the control plane on its own thread (docs/architecture/POLICY_SNAPSHOT_CONTRACT.md):
 * verifies the Ed25519 signature, parses strictly, and offers it to the engine, which activates only a higher version.
 * The last activated snapshot is kept in the cache directory and verified again at start-up.
 */
public final class SnapshotPoller implements Runnable {

    private static final String BODY = "snapshot.json";
    private static final String SIGNATURE = "snapshot.sig";
    private static final String KEY_ID = "snapshot.kid";

    private final IcapEngine engine;
    private final URI url;
    private final SnapshotVerifier verifier;
    private final Path cacheDir;
    private final Clock clock;
    private final Duration interval;
    private final HttpClient client;
    private final Map<String, LongAdder> refused = new ConcurrentHashMap<>();
    private volatile boolean running = true;

    public SnapshotPoller(IcapEngine engine, URI url, SnapshotVerifier verifier, Path cacheDir, Clock clock,
                          Duration interval) {
        this.engine = engine;
        this.url = url;
        this.verifier = verifier;
        this.cacheDir = cacheDir;
        this.clock = clock;
        this.interval = interval;
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    }

    /** Verifies and activates the cached snapshot, if any; staleness still applies. */
    public void loadCache() {
        if (cacheDir == null) {
            return;
        }
        try {
            Path body = cacheDir.resolve(BODY);
            if (!Files.exists(body)) {
                return;
            }
            offer(Files.readAllBytes(body), Files.readString(cacheDir.resolve(KEY_ID)).strip(),
                Files.readString(cacheDir.resolve(SIGNATURE)).strip(), false);
        } catch (IOException e) {
            count("CACHE_UNREADABLE");
        }
    }

    @Override
    public void run() {
        while (running) {
            pollOnce();
            try {
                Thread.sleep(interval.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    /** One request to the control plane; public for tests. */
    public void pollOnce() {
        IcapEngine.Policy active = engine.policy();
        HttpRequest.Builder b = HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(5)).GET();
        if (active != null) {
            b.header("If-None-Match", "\"" + active.snapshot().version() + "\"");
        }
        try {
            HttpResponse<byte[]> r = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
            if (r.statusCode() == 304) {
                return;
            }
            if (r.statusCode() != 200) {
                count("HTTP_" + r.statusCode());
                return;
            }
            offer(r.body(), r.headers().firstValue("X-RWSAFE-Key-Id").orElse(null),
                r.headers().firstValue("X-RWSAFE-Signature").orElse(null), true);
        } catch (IOException e) {
            count("UNREACHABLE");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void offer(byte[] body, String keyId, String signature, boolean persist) {
        PolicySnapshot snapshot;
        try {
            verifier.verify(body, keyId, signature);
            snapshot = SnapshotCodec.parse(body, clock.instant());
        } catch (SnapshotCodec.Rejected e) {
            count(e.reason());
            return;
        }
        if (engine.activate(snapshot) == IcapEngine.Activation.NOT_NEWER) {
            count("NOT_NEWER");
            return;
        }
        if (persist && cacheDir != null) {
            try {
                write(BODY, body);
                write(KEY_ID, keyId.getBytes(StandardCharsets.US_ASCII));
                write(SIGNATURE, signature.getBytes(StandardCharsets.US_ASCII));
            } catch (IOException e) {
                count("CACHE_UNWRITABLE");
            }
        }
    }

    private void write(String name, byte[] data) throws IOException {
        Files.createDirectories(cacheDir);
        Path tmp = cacheDir.resolve(name + ".tmp");
        Files.write(tmp, data);
        Files.move(tmp, cacheDir.resolve(name), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private void count(String reason) {
        refused.computeIfAbsent(reason, k -> new LongAdder()).increment();
    }

    /** Refusals by fixed reason token (metrics). */
    public Map<String, Long> refusals() {
        Map<String, Long> out = new java.util.TreeMap<>();
        refused.forEach((k, v) -> out.put(k, v.sum()));
        return out;
    }

    public void stop() {
        running = false;
    }
}
