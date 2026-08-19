-- Expiring, content-blind mailboxes for protected Device Sync enrollment.
-- The server stores only digests for the PIN/polling capability and an opaque
-- bootstrap encrypted to the candidate's locally created public key.
CREATE TABLE device_sync_join_requests (
    request_id UUID PRIMARY KEY,
    retry_id UUID NOT NULL UNIQUE,
    version INTEGER NOT NULL,
    candidate_device_id UUID NOT NULL,
    candidate_bootstrap_public_key TEXT NOT NULL,
    polling_authorization_digest TEXT NOT NULL,
    pin_authorization_digest TEXT NOT NULL,
    created_at_milliseconds BIGINT NOT NULL,
    expires_at_milliseconds BIGINT NOT NULL,
    principal_id UUID NULL REFERENCES device_sync_principals(principal_id),
    bootstrap JSONB NULL,
    CHECK ((principal_id IS NULL) = (bootstrap IS NULL))
);

CREATE INDEX device_sync_join_requests_pin_lookup
    ON device_sync_join_requests (pin_authorization_digest, expires_at_milliseconds DESC);
