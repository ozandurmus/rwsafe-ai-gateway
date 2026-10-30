package io.rwsafe.control.policy;

import io.rwsafe.persistence.PolicySnapshotStore.IssuedSnapshot;
import java.nio.charset.StandardCharsets;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code GET /internal/v1/policy/snapshot} exactly as POLICY_SNAPSHOT_CONTRACT says: the current snapshot document
 * (format 1), {@code ETag: "<version>"}, {@code X-RWSAFE-Key-Id}, {@code X-RWSAFE-Signature: ed25519:<base64>} over the
 * exact body bytes, and 304 when {@code If-None-Match} names the current version. Served on the snapshot-feed connector
 * (8091) only. Without a signing key or a complete registry the answer is 503 with its reason, never an unsigned or
 * partial snapshot: the data plane keeps its last good one (or stays not ready).
 */
@RestController
public class SnapshotFeedController {

    public static final String PATH = "/internal/v1/policy/snapshot";
    public static final String KEY_ID_HEADER = "X-RWSAFE-Key-Id";
    public static final String SIGNATURE_HEADER = "X-RWSAFE-Signature";

    private final PolicyRegistryService registry;
    private final SnapshotSigner signer;

    public SnapshotFeedController(PolicyRegistryService registry, SnapshotSigner signer) {
        this.registry = registry;
        this.signer = signer;
    }

    @GetMapping(PATH)
    public ResponseEntity<byte[]> snapshot(@RequestHeader(name = "If-None-Match", required = false) String ifNoneMatch) {
        if (!signer.available()) {
            throw new RegistryRefusal(HttpStatus.SERVICE_UNAVAILABLE, "SNAPSHOT_SIGNING_UNAVAILABLE",
                "The snapshot signing key is unavailable; no unsigned snapshot is served.");
        }
        IssuedSnapshot snapshot = registry.currentSnapshot();
        String etag = "\"" + snapshot.version() + "\"";
        if (matches(ifNoneMatch, etag)) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED).eTag(etag).cacheControl(CacheControl.noStore()).build();
        }
        byte[] body = snapshot.document().getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .eTag(etag)
            .cacheControl(CacheControl.noStore())
            .header(KEY_ID_HEADER, signer.keyId())
            .header(SIGNATURE_HEADER, signer.sign(body))
            .body(body);
    }

    /** {@code If-None-Match} as a list of entity tags; a weak tag compares by its value (RFC 9110 §13.1.2). */
    static boolean matches(String ifNoneMatch, String etag) {
        if (ifNoneMatch == null || ifNoneMatch.length() > 256) {
            return false;
        }
        for (String tag : ifNoneMatch.split(",")) {
            String t = tag.strip();
            if (t.startsWith("W/")) {
                t = t.substring(2);
            }
            if (t.equals(etag) || t.equals("*")) {
                return true;
            }
        }
        return false;
    }
}
