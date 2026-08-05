ALTER TABLE relay_domains
    ADD COLUMN maximum_blob_count integer NOT NULL DEFAULT 10000
        CHECK (maximum_blob_count > 0 AND maximum_blob_count <= 1000000),
    ADD COLUMN blob_count integer NOT NULL DEFAULT 0
        CHECK (blob_count >= 0);

ALTER TABLE relay_domains
    ADD CONSTRAINT relay_domains_blob_count_limit_check CHECK (
        blob_count <= maximum_blob_count
    );

CREATE TABLE relay_blobs (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    blob_id text NOT NULL CHECK (blob_id ~ '^[A-Za-z0-9_-]{43}$'),
    publisher_member_id uuid NOT NULL,
    byte_count bigint NOT NULL CHECK (
        byte_count >= 0 AND byte_count <= 268435456
    ),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, blob_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, publisher_member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
);

ALTER TABLE relay_audit_events
    ADD COLUMN blob_id text CHECK (blob_id ~ '^[A-Za-z0-9_-]{43}$'),
    DROP CONSTRAINT relay_audit_events_event_type_check,
    ADD CONSTRAINT relay_audit_events_event_type_check CHECK (event_type IN (
        'domain_created',
        'member_created',
        'member_revoked',
        'message_published',
        'message_accepted',
        'message_applied',
        'blob_published'
    )),
    ADD CONSTRAINT relay_audit_events_blob_event_check CHECK (
        (event_type = 'blob_published') = (blob_id IS NOT NULL)
    );

CREATE INDEX relay_blobs_publisher_idx
    ON relay_blobs (tenant_id, domain_id, publisher_member_id);
