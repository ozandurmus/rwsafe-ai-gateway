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
    static final Field<Integer> RV_WITHDRAWS = DSL.field(DSL.name("policy_rule_version", "withdraws_version"),
        SQLDataType.INTEGER);
    static final Field<String> RV_WITHDRAWAL_REASON = DSL.field(DSL.name("policy_rule_version", "withdrawal_reason"),
        SQLDataType.CLOB);
    static final Field<Instant> RV_WITHDRAWN_AT = DSL.field(DSL.name("policy_rule_version", "withdrawn_at"),
        SQLDataType.INSTANT);
    static final Field<String> RV_WITHDRAWN_BY = DSL.field(DSL.name("policy_rule_version", "withdrawn_by"),
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

    static final Table<Record> NOTICE_VERSION = DSL.table(DSL.name("notice_version"));
    static final Field<String> NV_VERSION = DSL.field(DSL.name("notice_version", "notice_version"), SQLDataType.CLOB);
    static final Field<Instant> NV_ISSUED_AT = DSL.field(DSL.name("notice_version", "issued_at"), SQLDataType.INSTANT);

    static final Table<Record> NOTICE_ACK = DSL.table(DSL.name("notice_acknowledgement"));
    static final Field<Long> NA_ID = DSL.field(DSL.name("notice_acknowledgement", "acknowledgement_id"),
        SQLDataType.BIGINT);
    static final Field<String> NA_USER = DSL.field(DSL.name("notice_acknowledgement", "user_pseudonym"),
        SQLDataType.CLOB);
    static final Field<String> NA_VERSION = DSL.field(DSL.name("notice_acknowledgement", "notice_version"),
        SQLDataType.CLOB);
    static final Field<Instant> NA_ACKNOWLEDGED_AT = DSL.field(DSL.name("notice_acknowledgement", "acknowledged_at"),
        SQLDataType.INSTANT);
    static final Field<String> NA_SOURCE = DSL.field(DSL.name("notice_acknowledgement", "source"), SQLDataType.CLOB);
    static final Field<Instant> NA_RECORDED_AT = DSL.field(DSL.name("notice_acknowledgement", "recorded_at"),
        SQLDataType.INSTANT);
    static final Field<String> NA_KEY_ID = DSL.field(DSL.name("notice_acknowledgement", "pseudonym_key_id"),
        SQLDataType.CLOB);

    static final Table<Record> CAPTURE_CHUNK = DSL.table(DSL.name("capture_chunk"));
    static final Field<UUID> CH_ID = DSL.field(DSL.name("capture_chunk", "chunk_id"), SQLDataType.UUID);
    static final Field<String> CH_ADDRESS = DSL.field(DSL.name("capture_chunk", "chunk_digest"), SQLDataType.CLOB);
    static final Field<String> CH_KEY_ID = DSL.field(DSL.name("capture_chunk", "key_id"), SQLDataType.CLOB);
    static final Field<byte[]> CH_WRAPPED_KEY = DSL.field(DSL.name("capture_chunk", "wrapped_key"), SQLDataType.BLOB);
    static final Field<Integer> CH_STORED_BYTES = DSL.field(DSL.name("capture_chunk", "stored_bytes"),
        SQLDataType.INTEGER);
    static final Field<Integer> CH_REF_COUNT = DSL.field(DSL.name("capture_chunk", "ref_count"), SQLDataType.INTEGER);

    static final Table<Record> CAPTURE = DSL.table(DSL.name("capture_record"));
    static final Field<UUID> CAP_EVENT_ID = DSL.field(DSL.name("capture_record", "event_id"), SQLDataType.UUID);
    static final Field<Instant> CAP_CAPTURED_AT = DSL.field(DSL.name("capture_record", "captured_at"),
        SQLDataType.INSTANT);
    static final Field<Instant> CAP_EXPIRES_AT = DSL.field(DSL.name("capture_record", "expires_at"),
        SQLDataType.INSTANT);
    static final Field<String> CAP_USER = DSL.field(DSL.name("capture_record", "user_pseudonym"), SQLDataType.CLOB);
    static final Field<String> CAP_KEY_ID = DSL.field(DSL.name("capture_record", "key_id"), SQLDataType.CLOB);
    static final Field<byte[]> CAP_WRAPPED_KEY = DSL.field(DSL.name("capture_record", "wrapped_key"), SQLDataType.BLOB);
    static final Field<byte[]> CAP_MAC = DSL.field(DSL.name("capture_record", "manifest_mac"), SQLDataType.BLOB);
    static final Field<Integer> CAP_PLAIN_BYTES = DSL.field(DSL.name("capture_record", "plain_bytes"),
        SQLDataType.INTEGER);
    static final Field<Boolean> CAP_TRUNCATED = DSL.field(DSL.name("capture_record", "truncated"), SQLDataType.BOOLEAN);
    static final Field<String> CAP_MASK_RULE_SET = DSL.field(DSL.name("capture_record", "mask_rule_set"),
        SQLDataType.CLOB);
    static final Field<Boolean> CAP_LEGAL_HOLD = DSL.field(DSL.name("capture_record", "legal_hold"),
        SQLDataType.BOOLEAN);

    static final Table<Record> CAPTURE_MANIFEST = DSL.table(DSL.name("capture_manifest"));
    static final Field<UUID> MF_EVENT_ID = DSL.field(DSL.name("capture_manifest", "event_id"), SQLDataType.UUID);
    static final Field<Short> MF_SEQ = DSL.field(DSL.name("capture_manifest", "seq"), SQLDataType.SMALLINT);
    static final Field<UUID> MF_CHUNK_ID = DSL.field(DSL.name("capture_manifest", "chunk_id"), SQLDataType.UUID);

    static final Table<Record> CAPTURE_USAGE = DSL.table(DSL.name("capture_store_usage"));
    static final Field<Long> USAGE_BYTES = DSL.field(DSL.name("capture_store_usage", "stored_bytes"),
        SQLDataType.BIGINT);

    static final Table<Record> CAPTURE_READ = DSL.table(DSL.name("capture_read"));
    static final Field<Long> CR_ID = DSL.field(DSL.name("capture_read", "read_id"), SQLDataType.BIGINT);
    static final Field<UUID> CR_EVENT_ID = DSL.field(DSL.name("capture_read", "event_id"), SQLDataType.UUID);
    static final Field<String> CR_ACTOR = DSL.field(DSL.name("capture_read", "actor_fingerprint"), SQLDataType.CLOB);
    static final Field<String> CR_REASON = DSL.field(DSL.name("capture_read", "reason_code"), SQLDataType.CLOB);
    static final Field<String> CR_CASE = DSL.field(DSL.name("capture_read", "case_id"), SQLDataType.CLOB);
    static final Field<String> CR_OUTCOME = DSL.field(DSL.name("capture_read", "outcome"), SQLDataType.CLOB);

    static final Table<Record> CAPTURE_RECEIPT = DSL.table(DSL.name("capture_deletion_receipt"));
    static final Field<String> RCPT_REASON = DSL.field(DSL.name("capture_deletion_receipt", "reason"),
        SQLDataType.CLOB);
    static final Field<String> RCPT_KEY_ID = DSL.field(DSL.name("capture_deletion_receipt", "key_id"),
        SQLDataType.CLOB);
    static final Field<UUID[]> RCPT_EVENT_IDS = DSL.field(DSL.name("capture_deletion_receipt", "event_ids"),
        SQLDataType.UUID.array());
    static final Field<Integer> RCPT_CHUNKS = DSL.field(DSL.name("capture_deletion_receipt", "chunk_count"),
        SQLDataType.INTEGER);

    static final Table<Record> CAPTURE_KEY_EVENT = DSL.table(DSL.name("capture_key_event"));
    static final Field<String> KE_OPERATION = DSL.field(DSL.name("capture_key_event", "operation"), SQLDataType.CLOB);
    static final Field<String> KE_FROM = DSL.field(DSL.name("capture_key_event", "from_key_id"), SQLDataType.CLOB);
    static final Field<String> KE_TO = DSL.field(DSL.name("capture_key_event", "to_key_id"), SQLDataType.CLOB);
    static final Field<Integer> KE_RECORDS = DSL.field(DSL.name("capture_key_event", "records"), SQLDataType.INTEGER);
    static final Field<Integer> KE_CHUNKS = DSL.field(DSL.name("capture_key_event", "chunks"), SQLDataType.INTEGER);

    static final Table<Record> AUDIT_EVENT = DSL.table(DSL.name("audit_event"));
    static final Field<String> AUDIT_ACTOR = DSL.field(DSL.name("audit_event", "actor_fingerprint"), SQLDataType.CLOB);
    static final Field<String> AUDIT_ACTION = DSL.field(DSL.name("audit_event", "action_id"), SQLDataType.CLOB);
    static final Field<String> AUDIT_REASON = DSL.field(DSL.name("audit_event", "reason_code"), SQLDataType.CLOB);
    static final Field<String> AUDIT_TABLE = DSL.field(DSL.name("audit_event", "table_name"), SQLDataType.CLOB);
    static final Field<String> AUDIT_OPERATION = DSL.field(DSL.name("audit_event", "operation"), SQLDataType.CLOB);
    static final Field<String> AUDIT_ROW_KEY = DSL.field(DSL.name("audit_event", "row_key"), SQLDataType.CLOB);
    static final Field<Long> AUDIT_ID = DSL.field(DSL.name("audit_event", "audit_id"), SQLDataType.BIGINT);
    static final Field<Instant> AUDIT_OCCURRED_AT = DSL.field(DSL.name("audit_event", "occurred_at"), SQLDataType.INSTANT);
    static final Field<String> AUDIT_CORRELATION = DSL.field(DSL.name("audit_event", "correlation_id"), SQLDataType.CLOB);

    // xid8 columns (V7): jOOQ has no xid8 type, so they are declared OTHER and read and bound as text.
    static final Field<Object> VERDICT_TX_ID = DSL.field(DSL.name("verdict_event", "tx_id"), SQLDataType.OTHER);
    static final Field<Object> AUDIT_TX_ID = DSL.field(DSL.name("audit_event", "tx_id"), SQLDataType.OTHER);

    static final Table<Record> SIEM_WATERMARK = DSL.table(DSL.name("siem_watermark"));
    static final Field<String> SW_DESTINATION = DSL.field(DSL.name("siem_watermark", "destination"), SQLDataType.CLOB);
    static final Field<Object> SW_VERDICT_TX_ID = DSL.field(DSL.name("siem_watermark", "verdict_tx_id"),
        SQLDataType.OTHER);
    static final Field<UUID> SW_VERDICT_EVENT_ID = DSL.field(DSL.name("siem_watermark", "verdict_event_id"),
        SQLDataType.UUID);
    static final Field<Object> SW_AUDIT_TX_ID = DSL.field(DSL.name("siem_watermark", "audit_tx_id"), SQLDataType.OTHER);
    static final Field<Long> SW_AUDIT_ID = DSL.field(DSL.name("siem_watermark", "audit_id"), SQLDataType.BIGINT);
    static final Field<String> SW_START_FROM = DSL.field(DSL.name("siem_watermark", "start_from"), SQLDataType.CLOB);
    static final Field<Long> SW_SKIPPED_AT_START = DSL.field(DSL.name("siem_watermark", "skipped_at_start"),
        SQLDataType.BIGINT);
    static final Field<Instant> SW_UPDATED_AT = DSL.field(DSL.name("siem_watermark", "updated_at"), SQLDataType.INSTANT);
}
