-- Explicit final-device retirement unpublishes a Spaces Sync group and fences
-- product-level reuse while preserving relay audit records and exact retry.
CREATE TABLE device_sync_principal_retirements (
    principal_id uuid PRIMARY KEY REFERENCES device_sync_principals(principal_id) ON DELETE CASCADE,
    retry_id uuid NOT NULL UNIQUE,
    device_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    retired_at_milliseconds bigint NOT NULL CHECK (retired_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (principal_id, retry_id)
        REFERENCES device_sync_device_revocations(principal_id, retry_id),
    FOREIGN KEY (principal_id, device_id)
        REFERENCES device_sync_devices(principal_id, device_id)
);
