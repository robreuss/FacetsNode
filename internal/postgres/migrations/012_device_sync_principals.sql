-- Device Sync product authority. Content keys and plaintext Space metadata are never stored here.
CREATE TABLE device_sync_account_admissions (
    admission_id uuid PRIMARY KEY,
    retry_id uuid NOT NULL UNIQUE,
    version smallint NOT NULL CHECK (version = 1),
    authorization_digest text NOT NULL CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    expires_at_milliseconds bigint NOT NULL CHECK (expires_at_milliseconds > created_at_milliseconds),
    claimed_at_milliseconds bigint,
    claimed_principal_id uuid,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((claimed_at_milliseconds IS NULL) = (claimed_principal_id IS NULL))
);

CREATE TABLE device_sync_principals (
    principal_id uuid PRIMARY KEY,
    claim_retry_id uuid NOT NULL UNIQUE,
    account_admission_id uuid NOT NULL UNIQUE REFERENCES device_sync_account_admissions(admission_id),
    tenant_id uuid NOT NULL UNIQUE REFERENCES relay_tenants(tenant_id) ON DELETE CASCADE,
    control_domain_id uuid NOT NULL,
    initial_device_id uuid NOT NULL,
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, control_domain_id)
        REFERENCES relay_domains(tenant_id, domain_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, control_domain_id, initial_device_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE device_sync_devices (
    principal_id uuid NOT NULL REFERENCES device_sync_principals(principal_id) ON DELETE CASCADE,
    device_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    control_domain_id uuid NOT NULL,
    control_member_id uuid NOT NULL,
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, device_id),
    UNIQUE (tenant_id, control_domain_id, control_member_id),
    FOREIGN KEY (tenant_id, control_domain_id, control_member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX device_sync_account_admissions_active_idx
    ON device_sync_account_admissions (expires_at_milliseconds)
    WHERE claimed_at_milliseconds IS NULL;
