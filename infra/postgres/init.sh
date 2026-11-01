#!/bin/sh
set -eu
# Executed only on first initialization of the PostgreSQL volume.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=app_password="$DB_APP_PASSWORD" --set=migrator_password="$DB_MIGRATOR_PASSWORD" <<'SQL'
CREATE ROLE investor_app LOGIN PASSWORD :'app_password';
CREATE ROLE investor_migrator LOGIN PASSWORD :'migrator_password';
CREATE ROLE pii_auditor NOLOGIN;
REVOKE ALL ON DATABASE investors FROM PUBLIC;
GRANT CONNECT ON DATABASE investors TO investor_app, investor_migrator, pii_auditor;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA investor AUTHORIZATION investor_migrator;
CREATE SCHEMA pii_archive AUTHORIZATION investor_migrator;
GRANT USAGE ON SCHEMA investor TO investor_app;
GRANT USAGE ON SCHEMA pii_archive TO investor_app, pii_auditor;
ALTER DEFAULT PRIVILEGES FOR ROLE investor_migrator IN SCHEMA investor, pii_archive REVOKE ALL ON TABLES FROM PUBLIC;
SQL
