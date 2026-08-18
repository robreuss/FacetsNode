-- One-time transport admission for an already enrolled Device Sync device to
-- one opaque Space domain. Content authority and keys remain client-held.
CREATE TABLE device_sync_space_device_admissions (
    principal_id uuid NOT NULL,
    space_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    device_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    admission_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    claimed_at_milliseconds bigint,
    claimed_member_id uuid,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, space_id, admission_id),
    UNIQUE (principal_id, space_id, retry_id),
    CHECK ((claimed_at_milliseconds IS NULL) = (claimed_member_id IS NULL)),
    FOREIGN KEY (principal_id, space_id)
        REFERENCES device_sync_spaces(principal_id, space_id) ON DELETE CASCADE,
    FOREIGN KEY (principal_id, device_id)
        REFERENCES device_sync_devices(principal_id, device_id) ON DELETE CASCADE,
    FOREIGN KEY (principal_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id) ON DELETE CASCADE,
    FOREIGN KEY (principal_id, domain_id, admission_id)
        REFERENCES relay_member_admissions(tenant_id, domain_id, admission_id) ON DELETE CASCADE,
    FOREIGN KEY (principal_id, domain_id, claimed_member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE UNIQUE INDEX device_sync_space_device_admissions_pending_device_idx
    ON device_sync_space_device_admissions (principal_id, space_id, device_id)
    WHERE claimed_at_milliseconds IS NULL;

CREATE INDEX device_sync_space_device_admissions_pending_idx
    ON device_sync_space_device_admissions (principal_id, space_id, created_at_milliseconds)
    WHERE claimed_at_milliseconds IS NULL;
