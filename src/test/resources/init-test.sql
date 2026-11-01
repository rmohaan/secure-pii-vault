CREATE ROLE investor_migrator LOGIN PASSWORD 'migration-test-only';
CREATE ROLE investor_app LOGIN PASSWORD 'app-test-only';
CREATE ROLE pii_auditor NOLOGIN;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA investor AUTHORIZATION investor_migrator;
CREATE SCHEMA pii_archive AUTHORIZATION investor_migrator;
GRANT USAGE ON SCHEMA investor TO investor_app;
GRANT USAGE ON SCHEMA pii_archive TO investor_app, pii_auditor;
