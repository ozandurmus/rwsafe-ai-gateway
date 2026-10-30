package io.rwsafe.policy;

import io.rwsafe.platform.verdict.DataClass;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * The compiled, immutable policy the inline path decides from (AGENTS.md section 6). Versions are monotonic (OFF2-11);
 * {@link #isTag()} changes with every snapshot so ProxySG re-validates (ICAP spec §4.2).
 *
 * <p>Registry, YAML import and signing arrive with the control plane; until then {@link Snapshots#builtinDevelopment()}
 * is the only source, and it is marked as such in its id.
 */
public final class PolicySnapshot {

    private final long version;
    private final String id;
    private final Map<DataClass, Action> classActions;
    private final boolean enforceFailClosed;
    private final List<PlatformRule> platforms;
    private final Instant issuedAt;
    private final List<ScopedRule> scopedRules;

    public PolicySnapshot(long version, String id, Map<DataClass, Action> classActions, boolean enforceFailClosed,
                          List<PlatformRule> platforms) {
        this(version, id, classActions, enforceFailClosed, platforms, null);
    }

    /** @param issuedAt when the control plane signed it; null for the built-in development snapshot (never stale) */
    public PolicySnapshot(long version, String id, Map<DataClass, Action> classActions, boolean enforceFailClosed,
                          List<PlatformRule> platforms, Instant issuedAt) {
        this(version, id, classActions, enforceFailClosed, platforms, issuedAt, List.of());
    }

    /**
     * Format 2 (POLICY_SNAPSHOT_CONTRACT.md): {@code classActions} is the {@code ANY} scope; {@code scopedRules} are the
     * group-scoped rules, resolved per transaction by {@link PolicyEvaluator#resolve}.
     */
    public PolicySnapshot(long version, String id, Map<DataClass, Action> classActions, boolean enforceFailClosed,
                          List<PlatformRule> platforms, Instant issuedAt, List<ScopedRule> scopedRules) {
        if (version < 1 || id == null || id.isBlank()) {
            throw new IllegalArgumentException("a snapshot needs a positive version and an id");
        }
        this.version = version;
        this.id = id;
        this.classActions = new EnumMap<>(classActions);
        for (DataClass c : DataClass.values()) {
            this.classActions.putIfAbsent(c, Action.BLOCK);
        }
        this.enforceFailClosed = enforceFailClosed;
        this.platforms = List.copyOf(platforms);
        this.issuedAt = issuedAt;
        this.scopedRules = List.copyOf(scopedRules);
    }

    public long version() {
        return version;
    }

    public String id() {
        return id;
    }

    /**
     * The {@code ANY}-scope action for a class; a class the snapshot does not name blocks (UNKNOWN fails closed, AGENTS.md
     * section 6). A transaction decides with {@link PolicyEvaluator#resolve}, which adds the scoped rules.
     */
    public Action actionFor(DataClass dataClass) {
        return classActions.get(dataClass);
    }

    /** True when the AI-category flow is an enforce-mode entry with fail-closed classes (ADR-010 "fail-closed flow"). */
    public boolean enforceFailClosed() {
        return enforceFailClosed;
    }

    /** True when signed longer ago than {@link SnapshotCodec#MAX_AGE}; the built-in snapshot is never stale (D-03). */
    public boolean isStale(Instant now) {
        return issuedAt != null && issuedAt.isBefore(now.minus(SnapshotCodec.MAX_AGE));
    }

    /** Null for the built-in development snapshot. */
    public Instant issuedAt() {
        return issuedAt;
    }

    /** Group-scoped rules (format 2), in snapshot order; empty for a format 1 snapshot. */
    public List<ScopedRule> scopedRules() {
        return scopedRules;
    }

    public List<PlatformRule> platforms() {
        return platforms;
    }

    /** ICAP ISTag value (quoted), at most 32 characters as RFC 3507 requires. */
    public String isTag() {
        String tag = "rw" + version + "-" + Integer.toHexString(id.hashCode());
        return "\"" + (tag.length() > 30 ? tag.substring(0, 30) : tag) + "\"";
    }
}
