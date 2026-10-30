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
    static final Field<String[]> APPLIED_RULE_IDS = DSL.field(DSL.name("verdict_event", "applied_rule_ids"),
        SQLDataType.CLOB.array());
    static final Field<String[]> MONITOR_RULE_IDS = DSL.field(DSL.name("verdict_event", "monitor_rule_ids"),
        SQLDataType.CLOB.array());
    static final Field<String> PSEUDONYM_KEY_ID =DSL.field(DSL.name("verdict_event", "pseudonym_key_id"), SQLDataType.CLOB);

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

    static final Table<Record> RULE_VERSION = DSL.table(DSL.name("policy_rule_version"));
    static final Field<String> RV_RULE_ID = DSL.field(DSL.name("policy_rule_version", "rule_id"), SQLDataType.CLOB);
    static final Field<Integer> RV_VERSION = DSL.field(DSL.name("policy_rule_version", "version"), SQLDataType.INTEGER);
    static final Field<String> RV_KIND = DSL.field(DSL.name("policy_rule_version", "kind"), SQLDataType.CLOB);
    static final Field<String> RV_DATA_CLASS = DSL.field(DSL.name("policy_rule_version", "data_class"), SQLDataType.CLOB);
    static final Field<String> RV_ACTION = DSL.field(DSL.name("policy_rule_version", "action"), SQLDataType.CLOB);
    static final Field<String> RV_PLATFORM = DSL.field(DSL.name("policy_rule_version", "platform_id"), SQLDataType.CLOB);
    static final Field<String[]> RV_HOST_SUFFIXES = DSL.field(DSL.name("policy_rule_version", "host_suffixes"),
        SQLDataType.CLOB.array());
    static final Field<String[]> RV_API_HOSTS = DSL.field(DSL.name("policy_rule_version", "api_hosts"),
        SQLDataType.CLOB.array());
    static final Field<String[]> RV_LOGIN_HOSTS = DSL.field(DSL.name("policy_rule_version", "login_hosts"),
        SQLDataType.CLOB.array());
    static final Field<Boolean> RV_ENFORCE_FAIL_CLOSED = DSL.field(DSL.name("policy_rule_version", "enforce_fail_closed"),
        SQLDataType.BOOLEAN);
    static final Field<String> RV_MODE = DSL.field(DSL.name("policy_rule_version", "mode"), SQLDataType.CLOB);
    static final Field<String> RV_STAGE = DSL.field(DSL.name("policy_rule_version", "rollout_stage"), SQLDataType.CLOB);
    static final Field<String> RV_STATUS = DSL.field(DSL.name("policy_rule_version", "status"), SQLDataType.CLOB);
    static final Field<String> RV_SOURCE = DSL.field(DSL.name("policy_rule_version", "source"), SQLDataType.CLOB);
    static final Field<String> RV_AUTHOR = DSL.field(DSL.name("policy_rule_version", "author_fingerprint"), SQLDataType.CLOB);
    static final Field<String> RV_REASON = DSL.field(DSL.name("policy_rule_version", "reason_code"), SQLDataType.CLOB);
    static final Field<Instant> RV_CREATED_AT = DSL.field(DSL.name("policy_rule_version", "created_at"),
        SQLDataType.INSTANT);
    static final Field<Instant> RV_ACTIVATED_AT = DSL.field(DSL.name("policy_rule_version", "activated_at"),
        SQLDataType.INSTANT);
    static final Field<Instant> RV_SUPERSEDED_AT = DSL.field(DSL.name("policy_rule_version", "superseded_at"),
        SQLDataType.INSTANT);
    static final Field<String> RV_SCOPE_KIND = DSL.field(DSL.name("policy_rule_version", "scope_kind"), SQLDataType.CLOB);
    static final Field<String[]> RV_SCOPE_GROUPS = DSL.field(DSL.name("policy_rule_version", "scope_groups"),
        SQLDataType.CLOB.array());
    static final Field<String> RV_SCOPE_KEY = DSL.field(DSL.name("policy_rule_version", "scope_key"), SQLDataType.CLOB);
    static final Field<Instant> RV_RETIRED_AT = DSL.field(DSL.name("policy_rule_version", "retired_at"),
        SQLDataType.INSTANT);
    static final Field<String> RV_RETIRED_BY = DSL.field(DSL.name("policy_rule_version", "retired_by"), SQLDataType.CLOB);
    static final Field<String> RV_RETIRED_REASON = DSL.field(DSL.name("policy_rule_version", "retired_reason"),
        SQLDataType.CLOB);

    static final Table<Record> APPROVAL = DSL.table(DSL.name("policy_approval"));
    static final Field<String> AP_RULE_ID = DSL.field(DSL.name("policy_approval", "rule_id"), SQLDataType.CLOB);
    static final Field<Integer> AP_VERSION = DSL.field(DSL.name("policy_approval", "version"), SQLDataType.INTEGER);
    static final Field<String> AP_ROLE = DSL.field(DSL.name("policy_approval", "approver_role"), SQLDataType.CLOB);
    static final Field<String> AP_APPROVER = DSL.field(DSL.name("policy_approval", "approver_fingerprint"),
        SQLDataType.CLOB);
    static final Field<Instant> AP_APPROVED_AT = DSL.field(DSL.name("policy_approval", "approved_at"), SQLDataType.INSTANT);

    static final Table<Record> SNAPSHOT = DSL.table(DSL.name("policy_snapshot"));
    static final Field<Long> SN_VERSION = DSL.field(DSL.name("policy_snapshot", "version"), SQLDataType.BIGINT);
    static final Field<String> SN_ID = DSL.field(DSL.name("policy_snapshot", "snapshot_id"), SQLDataType.CLOB);
    static final Field<Instant> SN_ISSUED_AT = DSL.field(DSL.name("policy_snapshot", "issued_at"), SQLDataType.INSTANT);
    static final Field<String> SN_RULES_DIGEST = DSL.field(DSL.name("policy_snapshot", "rules_digest"), SQLDataType.CLOB);
    static final Field<String> SN_DOCUMENT_SHA256 = DSL.field(DSL.name("policy_snapshot", "document_sha256"),
        SQLDataType.CLOB);
    static final Field<String> SN_DOCUMENT = DSL.field(DSL.name("policy_snapshot", "document"), SQLDataType.CLOB);
    static final Field<String[]> SN_RULE_VERSIONS = DSL.field(DSL.name("policy_snapshot", "rule_versions"),
        SQLDataType.CLOB.array());
    static final Field<String[]> SN_APPROVERS = DSL.field(DSL.name("policy_snapshot", "approvers"),
        SQLDataType.CLOB.array());

    static final Table<Record> AUDIT_EVENT = DSL.table(DSL.name("audit_event"));
    static final Field<String> AUDIT_ACTOR = DSL.field(DSL.name("audit_event", "actor_fingerprint"), SQLDataType.CLOB);
    static final Field<String> AUDIT_ACTION = DSL.field(DSL.name("audit_event", "action_id"), SQLDataType.CLOB);
    static final Field<String> AUDIT_REASON = DSL.field(DSL.name("audit_event", "reason_code"), SQLDataType.CLOB);
    static final Field<String> AUDIT_TABLE = DSL.field(DSL.name("audit_event", "table_name"), SQLDataType.CLOB);
    static final Field<String> AUDIT_OPERATION = DSL.field(DSL.name("audit_event", "operation"), SQLDataType.CLOB);
    static final Field<String> AUDIT_ROW_KEY = DSL.field(DSL.name("audit_event", "row_key"), SQLDataType.CLOB);
}
