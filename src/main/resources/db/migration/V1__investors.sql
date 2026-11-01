CREATE TABLE investor.investors (
    id UUID PRIMARY KEY,
    pan_envelope TEXT NOT NULL,
    aadhaar_envelope TEXT NOT NULL,
    profile_envelope TEXT NOT NULL,
    pan_hmac BYTEA NOT NULL CHECK (octet_length(pan_hmac) = 32),
    aadhaar_hmac BYTEA NOT NULL CHECK (octet_length(aadhaar_hmac) = 32),
    hmac_version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (hmac_version, pan_hmac),
    UNIQUE (hmac_version, aadhaar_hmac)
);
CREATE TABLE pii_archive.investor_archive (
    investor_id UUID PRIMARY KEY REFERENCES investor.investors(id),
    envelope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
REVOKE ALL ON ALL TABLES IN SCHEMA investor, pii_archive FROM PUBLIC;
GRANT SELECT, INSERT ON investor.investors TO investor_app;
GRANT INSERT ON pii_archive.investor_archive TO investor_app;
GRANT SELECT ON pii_archive.investor_archive TO pii_auditor;

-- Single active blind-index version. Runtime cannot UPDATE this safety latch.
CREATE TABLE investor.crypto_policy (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    hmac_version TEXT NOT NULL
);
GRANT SELECT, INSERT ON investor.crypto_policy TO investor_app;
