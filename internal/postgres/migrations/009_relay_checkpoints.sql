ALTER TABLE relay_domains
    ADD COLUMN checkpoint_activation_ordinal bigint NOT NULL DEFAULT 0
        CHECK (checkpoint_activation_ordinal >= 0);

CREATE TABLE relay_checkpoints (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    stage_retry_id uuid NOT NULL,
    candidate_digest text NOT NULL CHECK (candidate_digest ~ '^[0-9a-f]{64}$'),
    version smallint NOT NULL CHECK (version = 1),
    publisher_subscription_id uuid NOT NULL,
    publisher_member_id uuid NOT NULL,
    covered_through_sequence bigint NOT NULL CHECK (covered_through_sequence >= 0),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    state text NOT NULL DEFAULT 'staged'
        CHECK (state IN ('staged', 'activated', 'retired')),
    activation_retry_id uuid,
    activation_ordinal bigint CHECK (activation_ordinal > 0),
    activated_at_milliseconds bigint,
    start_sequence bigint CHECK (start_sequence >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, checkpoint_id),
    UNIQUE (tenant_id, domain_id, stage_retry_id),
    UNIQUE (tenant_id, domain_id, activation_retry_id),
    UNIQUE (tenant_id, domain_id, activation_ordinal),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, publisher_subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, domain_id, publisher_member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (state = 'staged' AND activation_retry_id IS NULL AND
            activation_ordinal IS NULL AND activated_at_milliseconds IS NULL AND
            start_sequence IS NULL) OR
        (state IN ('activated', 'retired') AND activation_retry_id IS NOT NULL AND
            activation_ordinal IS NOT NULL AND activated_at_milliseconds IS NOT NULL AND
            start_sequence IS NOT NULL)
    )
);

CREATE TABLE relay_checkpoint_retained_messages (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    message_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, domain_id, checkpoint_id, message_id),
    FOREIGN KEY (tenant_id, domain_id, checkpoint_id)
        REFERENCES relay_checkpoints(tenant_id, domain_id, checkpoint_id)
        ON DELETE CASCADE
);

CREATE TABLE relay_checkpoint_retained_blobs (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    blob_id text NOT NULL CHECK (blob_id ~ '^[A-Za-z0-9_-]{43}$'),
    PRIMARY KEY (tenant_id, domain_id, checkpoint_id, blob_id),
    FOREIGN KEY (tenant_id, domain_id, checkpoint_id)
        REFERENCES relay_checkpoints(tenant_id, domain_id, checkpoint_id)
        ON DELETE CASCADE
);

CREATE TABLE relay_checkpoint_required_subscriptions (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, domain_id, checkpoint_id, subscription_id),
    FOREIGN KEY (tenant_id, domain_id, checkpoint_id)
        REFERENCES relay_checkpoints(tenant_id, domain_id, checkpoint_id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE relay_checkpoint_deletion_messages (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    message_id uuid NOT NULL,
    domain_sequence bigint NOT NULL CHECK (domain_sequence > 0),
    byte_count bigint NOT NULL CHECK (byte_count > 0),
    collected_at_milliseconds bigint CHECK (collected_at_milliseconds >= 0),
    PRIMARY KEY (tenant_id, domain_id, checkpoint_id, message_id),
    UNIQUE (tenant_id, domain_id, checkpoint_id, domain_sequence),
    FOREIGN KEY (tenant_id, domain_id, checkpoint_id)
        REFERENCES relay_checkpoints(tenant_id, domain_id, checkpoint_id)
        ON DELETE CASCADE
);

CREATE TABLE relay_checkpoint_deletion_blobs (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    blob_id text NOT NULL CHECK (blob_id ~ '^[A-Za-z0-9_-]{43}$'),
    byte_count bigint NOT NULL CHECK (byte_count >= 0),
    collected_at_milliseconds bigint CHECK (collected_at_milliseconds >= 0),
    PRIMARY KEY (tenant_id, domain_id, checkpoint_id, blob_id),
    FOREIGN KEY (tenant_id, domain_id, checkpoint_id)
        REFERENCES relay_checkpoints(tenant_id, domain_id, checkpoint_id)
        ON DELETE CASCADE
);

CREATE TABLE relay_checkpoint_collections (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    plan_digest text NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    maximum_message_count bigint NOT NULL CHECK (
        maximum_message_count >= 0 AND maximum_message_count <= 10000
    ),
    maximum_blob_count bigint NOT NULL CHECK (
        maximum_blob_count >= 0 AND maximum_blob_count <= 10000
    ),
    requested_at_milliseconds bigint NOT NULL CHECK (requested_at_milliseconds >= 0),
    deleted_message_count bigint NOT NULL CHECK (deleted_message_count >= 0),
    deleted_message_byte_count bigint NOT NULL CHECK (deleted_message_byte_count >= 0),
    deleted_blob_count bigint NOT NULL CHECK (deleted_blob_count >= 0),
    deleted_blob_byte_count bigint NOT NULL CHECK (deleted_blob_byte_count >= 0),
    completed boolean NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, retry_id),
    FOREIGN KEY (tenant_id, domain_id, checkpoint_id)
        REFERENCES relay_checkpoints(tenant_id, domain_id, checkpoint_id)
        ON DELETE CASCADE,
    CHECK (maximum_message_count > 0 OR maximum_blob_count > 0)
);

CREATE TABLE relay_collected_blob_deletions (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    blob_id text NOT NULL CHECK (blob_id ~ '^[A-Za-z0-9_-]{43}$'),
    collected_at_milliseconds bigint NOT NULL CHECK (collected_at_milliseconds >= 0),
    PRIMARY KEY (tenant_id, domain_id, blob_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE
);

ALTER TABLE relay_audit_events ADD COLUMN checkpoint_id uuid;

CREATE INDEX relay_checkpoints_latest_idx
    ON relay_checkpoints (tenant_id, domain_id, activation_ordinal DESC)
    WHERE state = 'activated';
CREATE INDEX relay_checkpoint_messages_remaining_idx
    ON relay_checkpoint_deletion_messages
        (tenant_id, domain_id, checkpoint_id, domain_sequence)
    WHERE collected_at_milliseconds IS NULL;
CREATE INDEX relay_checkpoint_blobs_remaining_idx
    ON relay_checkpoint_deletion_blobs
        (tenant_id, domain_id, checkpoint_id, blob_id)
    WHERE collected_at_milliseconds IS NULL;
