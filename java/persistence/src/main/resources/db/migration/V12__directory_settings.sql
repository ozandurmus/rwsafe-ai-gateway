-- V12: the directory (LDAP) settings entered on the Administration screen and the binding of directory groups to roles
-- (PO decision Q-47, decision 1.2, Administration -> Access part 2,
-- docs/design/PO_DECISION_RECORD_2026_11_02_Q47_ADMIN_SECTION.md).
--
-- One row per settings version, append-only: a save never changes a row, it inserts the next version, and the highest
-- version is the active one. The history is never deleted (the ledger keeps naming each version by its number).
--
--   - The bind password is stored only sealed (AES-256-GCM under the product's own directory key, a Kubernetes Secret
--     the database never sees): format byte 0x01, a 12-byte nonce, the ciphertext and the 16-byte tag. NULL means no
--     password is set. The GCM associated data binds the value to its version, TLS mode, bind DN, URLs and CA bundle,
--     so a value copied to another row or other settings does not open; a save that keeps the password seals it again
--     for the new version, and only when the connection is unchanged (PR 50 review D-01).
--   - group_names and group_role_sets are the one source of directory group -> role bindings, position by position:
--     the group's name as the administrator entered it, and its roles separated by one space. The control plane
--     validates them (group names unique in the GroupNames comparison form, never a distinguished name); the guard
--     below refuses a comma or '=' in a name, checks the role vocabulary, each role once and the masked role alone.
--   - change_kind says what the version changed: 'seed' (the deploy's RWSAFE_LDAP_* values, copied once into an empty
--     table at start, by the system actor), 'connection' or 'group_roles' (a security_admin on the screen).
--   - The ledger row (audit trigger) is keyed by the version number; created_by must be the ledger's actor.
--
-- The URLs, distinguished names and group names here are directory identifiers: only a security_admin reads them, the
-- masked role reaches no route that shows them, and none of them is ever logged.

CREATE TABLE directory_settings (
    version               integer     PRIMARY KEY CHECK (version >= 1),
    created_at            timestamptz NOT NULL DEFAULT now(),
    created_by            text        NOT NULL CHECK (created_by ~ '^(USR-[0-9a-f]{10}|system:[a-z_-]{1,32})$'),
    change_kind           text        NOT NULL CHECK (change_kind IN ('seed', 'connection', 'group_roles')),
    reason                text        NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 500
                                                      AND reason !~ '[[:cntrl:]]'),
    enabled               boolean     NOT NULL,
    urls                  text[]      NOT NULL CHECK (cardinality(urls) BETWEEN 1 AND 8),
    tls_mode              text        NOT NULL CHECK (tls_mode IN ('ldaps', 'starttls', 'none')),
    ca_certificate_pem    text        CHECK (ca_certificate_pem IS NULL OR length(ca_certificate_pem) BETWEEN 1 AND 65536),
    bind_dn               text        NOT NULL CHECK (length(bind_dn) BETWEEN 1 AND 1024 AND bind_dn !~ '[[:cntrl:]]'),
    bind_password_sealed  bytea       CHECK (bind_password_sealed IS NULL
                                             OR (length(bind_password_sealed) BETWEEN 30 AND 2048
                                                 AND get_byte(bind_password_sealed, 0) = 1)),
    user_search_base      text        NOT NULL CHECK (length(user_search_base) BETWEEN 1 AND 1024
                                                      AND user_search_base !~ '[[:cntrl:]]'),
    user_search_filter    text        NOT NULL CHECK (length(user_search_filter) BETWEEN 3 AND 1024
                                                      AND strpos(user_search_filter, '{0}') > 0
                                                      AND user_search_filter !~ '[[:cntrl:]]'),
    group_attribute       text        CHECK (group_attribute IS NULL OR group_attribute ~ '^[A-Za-z][A-Za-z0-9-]{0,63}$'),
    group_search_base     text        CHECK (group_search_base IS NULL OR (length(group_search_base) BETWEEN 1 AND 1024
                                                                            AND group_search_base !~ '[[:cntrl:]]')),
    group_search_filter   text        CHECK (group_search_filter IS NULL
                                             OR (length(group_search_filter) BETWEEN 3 AND 1024
                                                 AND group_search_filter !~ '[[:cntrl:]]')),
    connect_timeout_ms    integer     NOT NULL CHECK (connect_timeout_ms BETWEEN 500 AND 30000),
    response_timeout_ms   integer     NOT NULL CHECK (response_timeout_ms BETWEEN 500 AND 60000),
    group_names           text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(group_names) <= 500),
    group_role_sets       text[]      NOT NULL DEFAULT '{}',
    CHECK (cardinality(group_names) = cardinality(group_role_sets)),
    -- A group search needs both its base and its filter.
    CHECK ((group_search_base IS NULL) = (group_search_filter IS NULL)),
    -- A CA bundle is PEM (public material, no key). Plain LDAP ('none') is for a loopback test directory only; the
    -- control plane checks the hosts, since a check here cannot resolve or parse a URL.
    CHECK (ca_certificate_pem IS NULL OR ca_certificate_pem LIKE '-----BEGIN %')
);

-- Versions are consecutive from 1, inserted by the actor the ledger names; a row never changes and is never deleted.
CREATE FUNCTION rwsafe_directory_settings_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    latest integer;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'DIRECTORY_SETTINGS_KEPT: a settings version is never changed or deleted; save a new one'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT max(version) INTO latest FROM directory_settings;
    IF NEW.version IS DISTINCT FROM coalesce(latest, 0) + 1 THEN
        RAISE EXCEPTION 'DIRECTORY_SETTINGS_VERSION: the next version is the latest plus one'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.created_by IS DISTINCT FROM nullif(btrim(current_setting('app.actor_fingerprint', true)), '') THEN
        RAISE EXCEPTION 'DIRECTORY_SETTINGS_ACTOR: the ledger actor is the one who saved the version'
            USING ERRCODE = 'check_violation';
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(NEW.group_names) AS g(name)
               WHERE name IS NULL OR length(btrim(name)) NOT BETWEEN 1 AND 256 OR name ~ '[[:cntrl:],=]')
        OR EXISTS (SELECT 1 FROM unnest(NEW.group_role_sets) AS r(roles)
                   WHERE roles IS NULL
                      OR roles !~ '^(security_admin|privacy_officer|viewer|replay_viewer)( (security_admin|privacy_officer|viewer))*$'
                      OR (roles LIKE '%replay_viewer%' AND roles <> 'replay_viewer')
                      OR (SELECT count(*) FROM regexp_split_to_table(roles, ' ') AS t(role))
                         <> (SELECT count(DISTINCT role) FROM regexp_split_to_table(roles, ' ') AS t(role))) THEN
        RAISE EXCEPTION 'DIRECTORY_GROUP_ROLES: group names without a comma or =, known roles once each, the masked role alone'
            USING ERRCODE = 'check_violation';
    END IF;
    -- Only the seed is the system's, and the system only seeds (PR 50 review D-07).
    IF (NEW.change_kind = 'seed') IS DISTINCT FROM (NEW.created_by LIKE 'system:%') THEN
        RAISE EXCEPTION 'DIRECTORY_SETTINGS_SEED_ACTOR: the system actor seeds, and only seeds'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.change_kind = 'seed' AND latest IS NOT NULL THEN
        RAISE EXCEPTION 'DIRECTORY_SETTINGS_SEED: the deploy values seed an empty table once, as the system actor'
            USING ERRCODE = 'check_violation';
    END IF;
    -- Group bindings change a saved connection; they are never the first version.
    IF NEW.change_kind = 'group_roles' AND latest IS NULL THEN
        RAISE EXCEPTION 'DIRECTORY_SETTINGS_GROUPS_FIRST: bind groups after a connection is saved'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER directory_settings_guard BEFORE INSERT OR UPDATE OR DELETE ON directory_settings
    FOR EACH ROW EXECUTE FUNCTION rwsafe_directory_settings_guard();
CREATE TRIGGER directory_settings_audit AFTER INSERT ON directory_settings
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('version');
CREATE TRIGGER directory_settings_no_truncate BEFORE TRUNCATE ON directory_settings
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();
