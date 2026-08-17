ALTER TABLE relay_tenants
    ADD COLUMN reserved_blob_count integer NOT NULL DEFAULT 0 CHECK (reserved_blob_count >= 0),
    ADD COLUMN reserved_blob_byte_count bigint NOT NULL DEFAULT 0 CHECK (reserved_blob_byte_count >= 0),
    ADD CHECK (blob_count + reserved_blob_count <= maximum_aggregate_blob_count),
    ADD CHECK (aggregate_blob_byte_count + reserved_blob_byte_count <= maximum_aggregate_blob_byte_count);

ALTER TABLE relay_domains
    ADD COLUMN reserved_blob_count integer NOT NULL DEFAULT 0 CHECK (reserved_blob_count >= 0),
    ADD COLUMN reserved_blob_byte_count bigint NOT NULL DEFAULT 0 CHECK (reserved_blob_byte_count >= 0),
    ADD CHECK (blob_count + reserved_blob_count <= maximum_blob_count),
    ADD CHECK (blob_byte_count + reserved_blob_byte_count <= maximum_blob_byte_count);

CREATE TABLE relay_blob_uploads (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    create_retry_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    publisher_member_id uuid NOT NULL,
    relay_blob_id text NOT NULL CHECK (relay_blob_id ~ '^[A-Za-z0-9_-]{43}$'),
    byte_count bigint NOT NULL CHECK (byte_count >= 0 AND byte_count <= 268435456),
    committed_offset bigint NOT NULL DEFAULT 0 CHECK (committed_offset >= 0 AND committed_offset <= byte_count),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'finalized', 'expired')),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    updated_at_milliseconds bigint NOT NULL CHECK (updated_at_milliseconds >= created_at_milliseconds),
    expires_at_milliseconds bigint NOT NULL CHECK (expires_at_milliseconds >= updated_at_milliseconds),
    finalized_at_milliseconds bigint,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, upload_id),
    UNIQUE (tenant_id, domain_id, create_retry_id),
    FOREIGN KEY (tenant_id, domain_id) REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id) REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id),
    FOREIGN KEY (tenant_id, domain_id, publisher_member_id) REFERENCES relay_members(tenant_id, domain_id, member_id),
    CHECK ((state = 'finalized') = (finalized_at_milliseconds IS NOT NULL)),
    CHECK (state <> 'finalized' OR committed_offset = byte_count)
);

CREATE TABLE relay_blob_upload_chunks (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    chunk_offset bigint NOT NULL CHECK (chunk_offset >= 0),
    byte_count bigint NOT NULL CHECK (byte_count > 0),
    chunk_sha256 text NOT NULL CHECK (chunk_sha256 ~ '^[0-9a-f]{64}$'),
    committed_at_milliseconds bigint NOT NULL CHECK (committed_at_milliseconds >= 0),
    PRIMARY KEY (tenant_id, domain_id, upload_id, chunk_offset),
    FOREIGN KEY (tenant_id, domain_id, upload_id)
        REFERENCES relay_blob_uploads(tenant_id, domain_id, upload_id) ON DELETE CASCADE
);

CREATE TABLE relay_blob_upload_finalizations (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    relay_blob_id text NOT NULL CHECK (relay_blob_id ~ '^[A-Za-z0-9_-]{43}$'),
    byte_count bigint NOT NULL CHECK (byte_count >= 0),
    finalized_at_milliseconds bigint NOT NULL CHECK (finalized_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, retry_id),
    FOREIGN KEY (tenant_id, domain_id, upload_id)
        REFERENCES relay_blob_uploads(tenant_id, domain_id, upload_id) ON DELETE CASCADE
);

CREATE TABLE relay_blob_upload_deletions (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    eligible_at_milliseconds bigint NOT NULL CHECK (eligible_at_milliseconds >= 0),
    PRIMARY KEY (tenant_id, domain_id, upload_id),
    FOREIGN KEY (tenant_id, domain_id) REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE
);

CREATE INDEX relay_blob_upload_expiry_idx
    ON relay_blob_uploads (expires_at_milliseconds) WHERE state = 'active';
