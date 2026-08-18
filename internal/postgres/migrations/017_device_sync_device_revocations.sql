-- Device Sync records the product-level meaning of an atomic relay membership
-- revocation. The referenced relay record fences the same device from its
-- control domain and every enrolled Space domain in one transaction.
CREATE TABLE device_sync_device_revocations (
    principal_id uuid NOT NULL REFERENCES device_sync_principals(principal_id) ON DELETE CASCADE,
    retry_id uuid NOT NULL,
    device_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    revoked_at_milliseconds bigint NOT NULL CHECK (revoked_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, retry_id),
    UNIQUE (principal_id, device_id),
    FOREIGN KEY (principal_id, device_id)
        REFERENCES device_sync_devices(principal_id, device_id),
    FOREIGN KEY (principal_id, retry_id)
        REFERENCES relay_tenant_membership_revocations(tenant_id, retry_id)
);
