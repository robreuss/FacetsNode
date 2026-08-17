-- Development checkpoint: the prior relay schema is deliberately rebuilt.
-- Facets is unreleased; no compatibility backfill or legacy authority remains.
DROP TABLE IF EXISTS relay_audit_events CASCADE;
DROP TABLE IF EXISTS relay_credential_rotations CASCADE;
DROP TABLE IF EXISTS relay_acknowledgments CASCADE;
DROP TABLE IF EXISTS relay_messages CASCADE;
DROP TABLE IF EXISTS relay_blobs CASCADE;
DROP TABLE IF EXISTS relay_member_admissions CASCADE;
DROP TABLE IF EXISTS relay_members CASCADE;
DROP TABLE IF EXISTS relay_subscription_status_changes CASCADE;
DROP TABLE IF EXISTS relay_subscriptions CASCADE;
DROP TABLE IF EXISTS relay_domains CASCADE;
DROP TABLE IF EXISTS relay_tenant_credential_rotations CASCADE;
DROP TABLE IF EXISTS relay_tenants CASCADE;

CREATE TABLE relay_tenants (
    tenant_id uuid PRIMARY KEY,
    version smallint NOT NULL CHECK (version = 1),
    provisioning_retry_id uuid NOT NULL UNIQUE,
    provisioning_authorization_digest text NOT NULL CHECK (provisioning_authorization_digest ~ '^[0-9a-f]{64}$'),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    maximum_domain_count integer NOT NULL CHECK (maximum_domain_count > 0),
    maximum_aggregate_message_count integer NOT NULL CHECK (maximum_aggregate_message_count > 0),
    maximum_aggregate_message_byte_count bigint NOT NULL CHECK (maximum_aggregate_message_byte_count > 0),
    maximum_aggregate_blob_count integer NOT NULL CHECK (maximum_aggregate_blob_count > 0),
    maximum_aggregate_blob_byte_count bigint NOT NULL CHECK (maximum_aggregate_blob_byte_count > 0),
    domain_count integer NOT NULL DEFAULT 0 CHECK (domain_count >= 0),
    message_count integer NOT NULL DEFAULT 0 CHECK (message_count >= 0),
    blob_count integer NOT NULL DEFAULT 0 CHECK (blob_count >= 0),
    aggregate_message_byte_count bigint NOT NULL DEFAULT 0 CHECK (aggregate_message_byte_count >= 0),
    aggregate_blob_byte_count bigint NOT NULL DEFAULT 0 CHECK (aggregate_blob_byte_count >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (domain_count <= maximum_domain_count),
    CHECK (message_count <= maximum_aggregate_message_count),
    CHECK (aggregate_message_byte_count <= maximum_aggregate_message_byte_count),
    CHECK (blob_count <= maximum_aggregate_blob_count),
    CHECK (aggregate_blob_byte_count <= maximum_aggregate_blob_byte_count)
);

CREATE TABLE relay_domains (
    tenant_id uuid NOT NULL REFERENCES relay_tenants(tenant_id) ON DELETE CASCADE,
    domain_id uuid NOT NULL,
    provisioning_retry_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    administration_digest text NOT NULL CHECK (administration_digest ~ '^[0-9a-f]{64}$'),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    maximum_message_count integer NOT NULL CHECK (maximum_message_count > 0),
    maximum_message_byte_count bigint NOT NULL CHECK (maximum_message_byte_count > 0),
    maximum_blob_count integer NOT NULL CHECK (maximum_blob_count > 0),
    maximum_blob_byte_count bigint NOT NULL CHECK (maximum_blob_byte_count > 0),
    message_count integer NOT NULL DEFAULT 0 CHECK (message_count >= 0),
    blob_count integer NOT NULL DEFAULT 0 CHECK (blob_count >= 0),
    message_byte_count bigint NOT NULL DEFAULT 0 CHECK (message_byte_count >= 0),
    blob_byte_count bigint NOT NULL DEFAULT 0 CHECK (blob_byte_count >= 0),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id),
    UNIQUE (tenant_id, provisioning_retry_id),
    CHECK (message_count <= maximum_message_count),
    CHECK (message_byte_count <= maximum_message_byte_count),
    CHECK (blob_count <= maximum_blob_count),
    CHECK (blob_byte_count <= maximum_blob_byte_count)
);

CREATE TABLE relay_subscriptions (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    create_retry_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    status text NOT NULL CHECK (status IN ('active', 'rebootstrap_required', 'revoked')),
    start_sequence bigint CHECK (start_sequence >= 0),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    updated_at_milliseconds bigint NOT NULL CHECK (updated_at_milliseconds >= created_at_milliseconds),
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, subscription_id),
    UNIQUE (tenant_id, domain_id, create_retry_id),
    FOREIGN KEY (tenant_id, domain_id) REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE
);

CREATE TABLE relay_subscription_status_changes (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('rebootstrap_required', 'revoked')),
    changed_at_milliseconds bigint NOT NULL CHECK (changed_at_milliseconds >= 0),
    result_start_sequence bigint CHECK (result_start_sequence >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, retry_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE relay_members (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    member_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    authorization_digest text NOT NULL CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
    capabilities text[] NOT NULL CHECK (cardinality(capabilities) > 0),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    expires_at_milliseconds bigint,
    revoked_at_milliseconds bigint,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, member_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (expires_at_milliseconds IS NULL OR expires_at_milliseconds > created_at_milliseconds),
    CHECK (revoked_at_milliseconds IS NULL OR revoked_at_milliseconds >= created_at_milliseconds)
);

CREATE TABLE relay_member_admissions (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    admission_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    authorization_digest text NOT NULL CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
    capabilities text[] NOT NULL CHECK (cardinality(capabilities) > 0),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    expires_at_milliseconds bigint NOT NULL,
    member_expires_at_milliseconds bigint,
    revoked_at_milliseconds bigint,
    claimed_at_milliseconds bigint,
    claimed_member_id uuid,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, admission_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, domain_id, claimed_member_id) REFERENCES relay_members(tenant_id, domain_id, member_id) DEFERRABLE INITIALLY DEFERRED,
    CHECK (expires_at_milliseconds > created_at_milliseconds),
    CHECK (member_expires_at_milliseconds IS NULL OR member_expires_at_milliseconds > expires_at_milliseconds),
    CHECK ((claimed_at_milliseconds IS NULL) = (claimed_member_id IS NULL))
);

CREATE TABLE relay_messages (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    domain_sequence bigint NOT NULL CHECK (domain_sequence > 0),
    message_id uuid NOT NULL,
    publisher_member_id uuid NOT NULL,
    publisher_subscription_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    algorithm text NOT NULL CHECK (algorithm = 'HKDF-SHA256+A256GCM'),
    key_epoch bigint NOT NULL CHECK (key_epoch > 0),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    nonce text NOT NULL,
    ciphertext text NOT NULL,
    authentication_tag text NOT NULL,
    ciphertext_byte_count integer NOT NULL CHECK (ciphertext_byte_count > 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, message_id),
    UNIQUE (tenant_id, domain_id, domain_sequence),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, publisher_member_id) REFERENCES relay_members(tenant_id, domain_id, member_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, domain_id, publisher_subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE relay_acknowledgments (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    message_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    stage text NOT NULL CHECK (stage IN ('accepted', 'applied')),
    accepted_at_milliseconds bigint NOT NULL CHECK (accepted_at_milliseconds >= 0),
    applied_at_milliseconds bigint,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, message_id, subscription_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, message_id) REFERENCES relay_messages(tenant_id, domain_id, message_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((stage = 'accepted' AND applied_at_milliseconds IS NULL) OR (stage = 'applied' AND applied_at_milliseconds IS NOT NULL))
);

CREATE TABLE relay_blobs (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    blob_id text NOT NULL,
    publisher_member_id uuid NOT NULL,
    byte_count bigint NOT NULL CHECK (byte_count >= 0 AND byte_count <= 268435456),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, blob_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, publisher_member_id) REFERENCES relay_members(tenant_id, domain_id, member_id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE relay_credential_rotations (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    rotation_id uuid NOT NULL,
    subject_type text NOT NULL CHECK (subject_type IN ('administration', 'member')),
    subject_id uuid NOT NULL,
    previous_authorization_digest text NOT NULL,
    new_authorization_digest text NOT NULL,
    rotated_at_milliseconds bigint NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, rotation_id),
    FOREIGN KEY (tenant_id, domain_id) REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE
);

CREATE TABLE relay_tenant_credential_rotations (
    tenant_id uuid NOT NULL REFERENCES relay_tenants(tenant_id) ON DELETE CASCADE,
    rotation_id uuid NOT NULL,
    previous_authorization_digest text NOT NULL,
    new_authorization_digest text NOT NULL,
    rotated_at_milliseconds bigint NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, rotation_id)
);

CREATE TABLE relay_audit_events (
    event_sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL,
    domain_id uuid,
    subscription_id uuid,
    member_id uuid,
    admission_id uuid,
    message_id uuid,
    blob_id text,
    credential_rotation_id uuid,
    event_type text NOT NULL,
    occurred_at_milliseconds bigint NOT NULL CHECK (occurred_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id) REFERENCES relay_tenants(tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE
);

CREATE INDEX relay_messages_fetch_idx ON relay_messages (tenant_id, domain_id, domain_sequence);
CREATE INDEX relay_members_subscription_idx ON relay_members (tenant_id, domain_id, subscription_id);
CREATE INDEX relay_admissions_subscription_idx ON relay_member_admissions (tenant_id, domain_id, subscription_id);
CREATE INDEX relay_audit_scope_idx ON relay_audit_events (tenant_id, domain_id, event_sequence);
