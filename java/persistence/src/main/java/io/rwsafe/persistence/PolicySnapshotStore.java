package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.jooq.impl.DSL;

/**
 * The issued policy snapshots (POLICY_SNAPSHOT_CONTRACT "Control plane behaviour"): each one is recorded with its version,
 * id, exact document, digest, rule versions and approvers, and ledgered. A new version is issued only when the active
 * rules changed or the latest snapshot is older than the refresh interval (the data plane refuses one older than 24 h);
 * otherwise the latest is served again, byte for byte. Issuing is serialised by a transaction-scoped advisory lock and
 * compiles the active rules inside it, so a version never carries an older rule set than the one before it.
 */
public final class PolicySnapshotStore {

    private final DSLContext dsl;
    private final PolicyRegistryStore registry;

    PolicySnapshotStore(DSLContext dsl, PolicyRegistryStore registry) {
        this.dsl = dsl;
        this.registry = registry;
    }

    /** One issued snapshot; {@code document} is the exact JSON the data plane receives and the signature covers. */
    public record IssuedSnapshot(long version, String snapshotId, Instant issuedAt, String rulesDigest,
                                 String documentSha256, String document, List<String> ruleVersions,
                                 List<String> approvers) {

        public IssuedSnapshot {
            ruleVersions = List.copyOf(ruleVersions);
            approvers = List.copyOf(approvers);
        }
    }

    /** Compiles the active rules; throws (and nothing is issued) when they do not make a complete snapshot. */
    public interface Compiler {
        Compiled compile(List<PolicyRuleVersion> active);
    }

    /** A compiled rule set before it has a version: its digest decides whether a new version is due. */
    public interface Compiled {

        /** A digest of everything the document carries except version, id and time. */
        String rulesDigest();

        List<String> ruleVersions();

        List<String> approvers();

        Rendered render(long version, Instant issuedAt);
    }

    public record Rendered(String snapshotId, String document) {
    }

    public Optional<IssuedSnapshot> latest() {
        return latest(dsl);
    }

    /**
     * The snapshot to serve now: the latest one when it compiles the same rules and is younger than {@code refreshAfter},
     * else a new version (latest + 1) issued at {@code now} and recorded under {@code audit}.
     */
    public IssuedSnapshot current(Compiler compiler, Instant now, Duration refreshAfter, AuditContext audit) {
        Optional<IssuedSnapshot> latest = latest(dsl);
        if (latest.isPresent() && reusable(latest.get(), compiler.compile(registry.active()), now, refreshAfter)) {
            return latest.get();
        }
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            tx.select(DSL.field("pg_advisory_xact_lock(hashtext('rwsafe.policy_snapshot.issue'))")).fetch();
            Compiled compiled = compiler.compile(PolicyRegistryStore.activeIn(tx));
            Optional<IssuedSnapshot> last = latest(tx);
            if (last.isPresent() && reusable(last.get(), compiled, now, refreshAfter)) {
                return last.get();
            }
            long version = last.map(s -> s.version() + 1).orElse(1L);
            // Always the issuing time: a stored issued_at in the future is never carried forward (PR 16 review D-02).
            Instant issuedAt = now;
            Rendered rendered = compiled.render(version, issuedAt);
            IssuedSnapshot issued = new IssuedSnapshot(version, rendered.snapshotId(), issuedAt, compiled.rulesDigest(),
                sha256(rendered.document()), rendered.document(), compiled.ruleVersions(), compiled.approvers());
            audit.apply(tx);
            tx.insertInto(SNAPSHOT, SN_VERSION, SN_ID, SN_ISSUED_AT, SN_RULES_DIGEST, SN_DOCUMENT_SHA256, SN_DOCUMENT,
                    SN_RULE_VERSIONS, SN_APPROVERS)
                .values(issued.version(), issued.snapshotId(), issued.issuedAt(), issued.rulesDigest(),
                    issued.documentSha256(), issued.document(), issued.ruleVersions().toArray(String[]::new),
                    issued.approvers().toArray(String[]::new))
                .execute();
            return issued;
        });
    }

    /**
     * The stored snapshot is served again only when it is exactly what this control plane would issue now for that
     * version and time: the same rules, not issued in the future, younger than the refresh interval, its stored digest
     * matching its document, and its document byte-identical to the compiler's rendering. A row written past the
     * application (a direct database write) is therefore never signed; a new version is issued from the active rules
     * instead (PR 16 review D-02).
     */
    static boolean reusable(IssuedSnapshot latest, Compiled compiled, Instant now, Duration refreshAfter) {
        return latest.rulesDigest().equals(compiled.rulesDigest())
            && !latest.issuedAt().isAfter(now)
            && latest.issuedAt().plus(refreshAfter).isAfter(now)
            && latest.documentSha256().equals(sha256(latest.document()))
            && compiled.render(latest.version(), latest.issuedAt()).document().equals(latest.document())
            && compiled.render(latest.version(), latest.issuedAt()).snapshotId().equals(latest.snapshotId());
    }

    private static Optional<IssuedSnapshot> latest(DSLContext ctx) {
        Record r = ctx.select(SN_VERSION, SN_ID, SN_ISSUED_AT, SN_RULES_DIGEST, SN_DOCUMENT_SHA256, SN_DOCUMENT,
            SN_RULE_VERSIONS, SN_APPROVERS).from(SNAPSHOT).orderBy(SN_VERSION.desc()).limit(1).fetchOne();
        if (r == null) {
            return Optional.empty();
        }
        return Optional.of(new IssuedSnapshot(r.get(SN_VERSION), r.get(SN_ID), r.get(SN_ISSUED_AT),
            r.get(SN_RULES_DIGEST), r.get(SN_DOCUMENT_SHA256), r.get(SN_DOCUMENT), List.of(r.get(SN_RULE_VERSIONS)),
            List.of(r.get(SN_APPROVERS))));
    }

    static String sha256(String document) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(document.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is part of every JDK", e);
        }
    }
}
