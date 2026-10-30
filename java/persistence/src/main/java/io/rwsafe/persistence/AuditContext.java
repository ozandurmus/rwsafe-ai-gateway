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
