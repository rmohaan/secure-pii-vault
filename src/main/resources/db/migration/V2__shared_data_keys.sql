-- Seed identities only here: a missing row at runtime is a fatal error, never a new DEK.
CREATE TABLE investor.data_keys (
    id TEXT PRIMARY KEY CHECK (id IN ('field', 'archive')),
    kek_resource TEXT,
    wrapped_dek BYTEA,
    revision BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ,
    CHECK ((revision = 0 AND kek_resource IS NULL AND wrapped_dek IS NULL AND updated_at IS NULL)
        OR (revision > 0 AND kek_resource IS NOT NULL AND wrapped_dek IS NOT NULL AND updated_at IS NOT NULL))
);
INSERT INTO investor.data_keys(id) VALUES ('field'), ('archive');
REVOKE ALL ON investor.data_keys FROM PUBLIC;
GRANT SELECT ON investor.data_keys TO investor_app, pii_auditor;
GRANT UPDATE (kek_resource, wrapped_dek, revision, updated_at) ON investor.data_keys TO investor_app;
