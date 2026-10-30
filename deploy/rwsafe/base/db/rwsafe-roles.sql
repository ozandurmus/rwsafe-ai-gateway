-- ADR-002 §1-§2: two roles. The image's POSTGRESQL_USER, rwsafe_migrate, owns the database and the public schema and runs
-- Flyway's DDL (the control plane's migrate data source). rwsafe_app is the control plane's DML role: it reads and writes
-- rows and creates nothing. Run as the superuser over the local socket on every start (rwsafe-roles.sh); idempotent.
-- Plain SQL so the persistence test (TwoRoleMigrationTest) runs this very file against Flyway's migrations.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rwsafe_app') THEN
        CREATE ROLE rwsafe_app LOGIN;
    END IF;
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO rwsafe_migrate, rwsafe_app', current_database());
END
$$;
ALTER ROLE rwsafe_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- PR 23 confirmation review D-11 / Q-SIEM-3: the SIEM export reads only rows below the oldest open transaction (V7), so
-- a session left idle inside a transaction would pause the export for as long as it stays open. Both application roles
-- abort such a session after 60 s; the export then resumes, and Health shows any longer stall. Superuser sessions (the
-- operator's psql) are not covered: an operator never leaves a transaction open on this database.
ALTER ROLE rwsafe_app SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE rwsafe_migrate SET idle_in_transaction_session_timeout = '60s';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO rwsafe_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rwsafe_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO rwsafe_app;
ALTER DEFAULT PRIVILEGES FOR ROLE rwsafe_migrate IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO rwsafe_app;
ALTER DEFAULT PRIVILEGES FOR ROLE rwsafe_migrate IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO rwsafe_app;
