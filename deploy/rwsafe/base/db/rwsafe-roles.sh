# Sourced (never executed) by the sclorg image's run script on every start, while the server runs locally on its socket
# only (the image's `postgresql-start/` extension point). ADR-002 §1-§2: rwsafe-roles.sql creates the DML role and its
# grants; the password of rwsafe_app is then set from the Secret through the environment, never an argument, and with
# statement logging off for that session so it can never reach the server log. UNVERIFIED (2026-10-30) on the pinned
# image digest: the extension directory and the running local server; verify with the first-installation dry run
# (DEPLOY_AND_SHARED_HOST_RUNBOOK §4): `\du` shows rwsafe_app, and Flyway's tables are owned by rwsafe_migrate.
psql -v ON_ERROR_STOP=1 --quiet --dbname "$POSTGRESQL_DATABASE" \
    --file /opt/app-root/src/postgresql-start/rwsafe-roles.sql
psql -v ON_ERROR_STOP=1 --quiet --dbname "$POSTGRESQL_DATABASE" <<'SQL'
SET log_statement = 'none';
SET log_min_duration_statement = -1;
\getenv app_credential RWSAFE_APP_PASSWORD
ALTER ROLE rwsafe_app WITH PASSWORD
    :'app_credential';
SQL
unset RWSAFE_APP_PASSWORD
