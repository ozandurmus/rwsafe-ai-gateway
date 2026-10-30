package io.rwsafe.persistence;

import java.time.Instant;
import java.util.UUID;
import org.jooq.Field;
import org.jooq.Record;
import org.jooq.Table;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

/**
 * The tables and columns of {@code db/migration} as jOOQ objects. Hand-written instead of generated, so the build needs no
 * database; {@code SchemaMatchesMigrationsTest} proves every name here exists with this type after the migrations run.
 */
final class Schema {

    private Schema() {
    }

    static final Table<Record> VERDICT_EVENT = DSL.table(DSL.name("verdict_event"));
    static final Field<UUID> EVENT_ID = DSL.field(DSL.name("verdict_event", "event_id"), SQLDataType.UUID);
    static final Field<Instant> RECEIVED_AT = DSL.field(DSL.name("verdict_event", "received_at"), SQLDataType.INSTANT);
    static final Field<Instant> INGESTED_AT = DSL.field(DSL.name("verdict_event", "ingested_at"), SQLDataType.INSTANT);
    static final Field<String> SERVICE = DSL.field(DSL.name("verdict_event", "service"), SQLDataType.CLOB);
    static final Field<String> PLATFORM = DSL.field(DSL.name("verdict_event", "platform"), SQLDataType.CLOB);
    static final Field<String> SURFACE = DSL.field(DSL.name("verdict_event", "surface"), SQLDataType.CLOB);
    static final Field<String> STEP = DSL.field(DSL.name("verdict_event", "step"), SQLDataType.CLOB);
    static final Field<String> VERDICT = DSL.field(DSL.name("verdict_event", "verdict"), SQLDataType.CLOB);
    static final Field<String> REASON = DSL.field(DSL.name("verdict_event", "reason"), SQLDataType.CLOB);
    static final Field<Long> BODY_BYTES = DSL.field(DSL.name("verdict_event", "body_bytes"), SQLDataType.BIGINT);
    static final Field<Long> DECISION_MICROS = DSL.field(DSL.name("verdict_event", "decision_micros"), SQLDataType.BIGINT);
    static final Field<String> USER_PSEUDONYM = DSL.field(DSL.name("verdict_event", "user_pseudonym"), SQLDataType.CLOB);
    static final Field<String> CLIENT_SUBNET = DSL.field(DSL.name("verdict_event", "client_subnet"), SQLDataType.CLOB);
    static final Field<String> TRANSPORT = DSL.field(DSL.name("verdict_event", "transport"), SQLDataType.CLOB);
    static final Field<Long> SNAPSHOT_VERSION = DSL.field(DSL.name("verdict_event", "snapshot_version"), SQLDataType.BIGINT);
    static final Field<String> CORRELATION_ID = DSL.field(DSL.name("verdict_event", "correlation_id"), SQLDataType.CLOB);
    static final Field<String> PSEUDONYM_KEY_ID = DSL.field(DSL.name("verdict_event", "pseudonym_key_id"), SQLDataType.CLOB);

    static final Table<Record> VERDICT_FINDING = DSL.table(DSL.name("verdict_finding"));
    static final Field<UUID> FINDING_EVENT_ID = DSL.field(DSL.name("verdict_finding", "event_id"), SQLDataType.UUID);
    static final Field<String> DATA_CLASS = DSL.field(DSL.name("verdict_finding", "data_class"), SQLDataType.CLOB);
    static final Field<Integer> HIT_COUNT = DSL.field(DSL.name("verdict_finding", "hit_count"), SQLDataType.INTEGER);
    static final Field<String> DIGEST = DSL.field(DSL.name("verdict_finding", "digest"), SQLDataType.CLOB);

    static final Table<Record> LOCAL_ACCOUNT = DSL.table(DSL.name("local_account"));
    static final Field<String> ACCOUNT_NAME = DSL.field(DSL.name("local_account", "account_name"), SQLDataType.CLOB);
    static final Field<String> PASSWORD_HASH = DSL.field(DSL.name("local_account", "password_hash"), SQLDataType.CLOB);
    static final Field<String[]> ROLES = DSL.field(DSL.name("local_account", "roles"), SQLDataType.CLOB.array());
    static final Field<Boolean> ENABLED = DSL.field(DSL.name("local_account", "enabled"), SQLDataType.BOOLEAN);

    static final Table<Record> LOGIN_RECORD = DSL.table(DSL.name("login_record"));
    static final Field<String> LOGIN_ACTOR = DSL.field(DSL.name("login_record", "actor_fingerprint"), SQLDataType.CLOB);
    static final Field<String> LOGIN_SOURCE = DSL.field(DSL.name("login_record", "source"), SQLDataType.CLOB);
    static final Field<Boolean> LOGIN_MASKED = DSL.field(DSL.name("login_record", "masked"), SQLDataType.BOOLEAN);

    static final Table<Record> AUDIT_EVENT = DSL.table(DSL.name("audit_event"));
    static final Field<String> AUDIT_ACTOR = DSL.field(DSL.name("audit_event", "actor_fingerprint"), SQLDataType.CLOB);
    static final Field<String> AUDIT_ACTION = DSL.field(DSL.name("audit_event", "action_id"), SQLDataType.CLOB);
    static final Field<String> AUDIT_REASON = DSL.field(DSL.name("audit_event", "reason_code"), SQLDataType.CLOB);
    static final Field<String> AUDIT_TABLE = DSL.field(DSL.name("audit_event", "table_name"), SQLDataType.CLOB);
    static final Field<String> AUDIT_OPERATION = DSL.field(DSL.name("audit_event", "operation"), SQLDataType.CLOB);
    static final Field<String> AUDIT_ROW_KEY = DSL.field(DSL.name("audit_event", "row_key"), SQLDataType.CLOB);
}
