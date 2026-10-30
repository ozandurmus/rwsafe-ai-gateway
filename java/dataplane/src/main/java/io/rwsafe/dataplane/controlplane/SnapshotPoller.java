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

    /** One file holding key id, signature and body, replaced atomically, so they can never disagree (D-08). */
    private static final String ENVELOPE = "snapshot.envelope";
    private static final int MAX_BODY = 1024 * 1024;

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
            Path envelope = cacheDir.resolve(ENVELOPE);
            if (!Files.exists(envelope) || Files.size(envelope) > 2L * MAX_BODY) {
                return;
            }
            String text = Files.readString(envelope, StandardCharsets.US_ASCII);
            int a = text.indexOf('\n');
            int b = a < 0 ? -1 : text.indexOf('\n', a + 1);
            if (b < 0) {
                count("CACHE_UNREADABLE");
                return;
            }
            byte[] body = java.util.Base64.getDecoder().decode(text.substring(b + 1).strip());
            offer(body, text.substring(0, a), text.substring(a + 1, b), false);
        } catch (IOException | IllegalArgumentException e) {
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
            HttpResponse<java.io.InputStream> r = client.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
            byte[] body;
            try (java.io.InputStream in = r.body()) {
                // Never buffer more than the contract allows (D-08).
                body = in.readNBytes(MAX_BODY + 1);
            }
            if (r.statusCode() == 304) {
                return;
            }
            if (r.statusCode() != 200) {
                count("HTTP_" + r.statusCode());
                return;
            }
            if (body.length > MAX_BODY) {
                count("TOO_LARGE");
                return;
            }
            offer(body, r.headers().firstValue("X-RWSAFE-Key-Id").orElse(null),
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
                write(ENVELOPE, (keyId + "\n" + signature + "\n" + java.util.Base64.getEncoder().encodeToString(body))
                    .getBytes(StandardCharsets.US_ASCII));
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
