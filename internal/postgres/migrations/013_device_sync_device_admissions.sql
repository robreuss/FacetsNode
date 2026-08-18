-- Product-level binding between a Device Sync principal/device and the opaque
-- relay admission used to join its encrypted principal control channel.
-- Claiming this admission grants transport membership only. Content trust and
-- keys remain client-held authority transferred over that control channel.
CREATE TABLE device_sync_device_admissions (
    principal_id uuid NOT NULL REFERENCES device_sync_principals(principal_id) ON DELETE CASCADE,
    retry_id uuid NOT NULL UNIQUE,
    device_id uuid NOT NULL,
    control_domain_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    admission_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    claimed_at_milliseconds bigint,
    claimed_member_id uuid,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, admission_id),
    CHECK ((claimed_at_milliseconds IS NULL) = (claimed_member_id IS NULL)),
    FOREIGN KEY (principal_id, control_domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id) ON DELETE CASCADE,
    FOREIGN KEY (principal_id, control_domain_id, admission_id)
        REFERENCES relay_member_admissions(tenant_id, domain_id, admission_id) ON DELETE CASCADE,
    FOREIGN KEY (principal_id, control_domain_id, claimed_member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE UNIQUE INDEX device_sync_device_admissions_pending_device_idx
    ON device_sync_device_admissions (principal_id, device_id)
    WHERE claimed_at_milliseconds IS NULL;

CREATE INDEX device_sync_device_admissions_pending_idx
    ON device_sync_device_admissions (principal_id, created_at_milliseconds)
    WHERE claimed_at_milliseconds IS NULL;
