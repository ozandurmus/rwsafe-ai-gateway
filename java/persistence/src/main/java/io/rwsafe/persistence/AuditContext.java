package io.rwsafe.persistence;

import java.util.Objects;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;

/**
 * Who changes what and why (ARCHITECTURE.md §4.4): set as transaction-local {@code app.*} settings before a mutation of an
 * audited table, read by the {@code rwsafe_audit_row} trigger, which refuses the mutation when any field is missing.
 *
 * @param actorFingerprint the actor's pseudonymous fingerprint or a {@code system:} actor, never a raw name
 */
public record AuditContext(String actorFingerprint, String actionId, String reasonCode, String correlationId) {

    public AuditContext {
        Objects.requireNonNull(actorFingerprint, "actorFingerprint");
        Objects.requireNonNull(actionId, "actionId");
        Objects.requireNonNull(reasonCode, "reasonCode");
        if (!actor(actorFingerprint) || actionId.isBlank() || reasonCode.isBlank()) {
            // The trigger refuses the same; failing here names the defect before a round trip (PR 12 review D-07).
            throw new IllegalArgumentException("an audit context needs a USR- or system: actor, an action and a reason");
        }
    }

    /** {@code USR-<10 hex>} or {@code system:<name>}: never a raw name. */
    static boolean actor(String s) {
        if (s.startsWith("system:")) {
            String name = s.substring("system:".length());
            return !name.isEmpty() && name.length() <= 32 && name.chars().allMatch(c -> (c >= 'a' && c <= 'z') || c == '_'
                || c == '-');
        }
        return s.length() == 14 && s.startsWith("USR-")
            && s.substring(4).chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }

    /** Must run inside the transaction whose mutations it describes ({@code set_config(..., true)} is local to it). */
    void apply(DSLContext tx) {
        tx.select(
            DSL.field("set_config('app.actor_fingerprint', {0}, true)", String.class, DSL.val(actorFingerprint)),
            DSL.field("set_config('app.action_id', {0}, true)", String.class, DSL.val(actionId)),
            DSL.field("set_config('app.reason_code', {0}, true)", String.class, DSL.val(reasonCode)),
            DSL.field("set_config('app.correlation_id', {0}, true)", String.class,
                DSL.val(correlationId == null ? "" : correlationId)))
            .fetch();
    }
}
