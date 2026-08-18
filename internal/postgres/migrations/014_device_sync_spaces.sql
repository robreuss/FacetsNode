-- Product-level binding from one opaque Facets Space identifier to its
-- isolated encrypted relay domain. Space names, content keys, FEF graphs, and
-- plaintext content never enter this table or the Device Sync service.
CREATE TABLE device_sync_spaces (
    principal_id uuid NOT NULL REFERENCES device_sync_principals(principal_id) ON DELETE CASCADE,
    space_id uuid NOT NULL,
    provisioning_retry_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    initial_device_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, space_id),
    UNIQUE (principal_id, provisioning_retry_id),
    UNIQUE (principal_id, domain_id),
    FOREIGN KEY (principal_id, initial_device_id)
        REFERENCES device_sync_devices(principal_id, device_id),
    FOREIGN KEY (principal_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE
);

CREATE INDEX device_sync_spaces_created_idx
    ON device_sync_spaces (principal_id, created_at_milliseconds, space_id);
