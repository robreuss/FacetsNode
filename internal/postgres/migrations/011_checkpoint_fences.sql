CREATE TABLE relay_checkpoint_fences (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    fence_id uuid NOT NULL,
    create_retry_id uuid NOT NULL,
    holder_subscription_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('active','activated','expired','aborted')),
    boundary_sequence bigint NOT NULL CHECK (boundary_sequence >= 0),
    requested_at_milliseconds bigint NOT NULL CHECK (requested_at_milliseconds >= 0),
    acquired_at_milliseconds bigint NOT NULL CHECK (acquired_at_milliseconds >= 0),
    expires_at_milliseconds bigint NOT NULL CHECK (expires_at_milliseconds > acquired_at_milliseconds),
    abort_retry_id uuid,
    aborted_at_milliseconds bigint,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,domain_id,fence_id),
    UNIQUE (tenant_id,domain_id,create_retry_id),
    UNIQUE (tenant_id,domain_id,abort_retry_id),
    FOREIGN KEY (tenant_id,domain_id) REFERENCES relay_domains(tenant_id,domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,domain_id,holder_subscription_id) REFERENCES relay_subscriptions(tenant_id,domain_id,subscription_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX relay_checkpoint_fences_one_active
    ON relay_checkpoint_fences (tenant_id,domain_id) WHERE status='active';

ALTER TABLE relay_checkpoints ADD COLUMN fence_id uuid NOT NULL;
ALTER TABLE relay_checkpoints ADD CONSTRAINT relay_checkpoints_fence_fk
    FOREIGN KEY (tenant_id,domain_id,fence_id)
    REFERENCES relay_checkpoint_fences(tenant_id,domain_id,fence_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE relay_messages ADD COLUMN checkpoint_fence_id uuid;
ALTER TABLE relay_messages ADD COLUMN envelope_digest text NOT NULL CHECK (envelope_digest ~ '^[0-9a-f]{64}$');
ALTER TABLE relay_messages ADD CONSTRAINT relay_messages_checkpoint_fence_fk
    FOREIGN KEY (tenant_id,domain_id,checkpoint_fence_id)
    REFERENCES relay_checkpoint_fences(tenant_id,domain_id,fence_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE relay_blobs ADD COLUMN checkpoint_fence_id uuid;
ALTER TABLE relay_blobs ADD CONSTRAINT relay_blobs_checkpoint_fence_fk
    FOREIGN KEY (tenant_id,domain_id,checkpoint_fence_id)
    REFERENCES relay_checkpoint_fences(tenant_id,domain_id,fence_id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE relay_checkpoint_fence_message_tombstones (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    message_id uuid NOT NULL,
    fence_id uuid NOT NULL,
    publisher_member_id uuid NOT NULL,
    envelope_digest text NOT NULL CHECK (envelope_digest ~ '^[0-9a-f]{64}$'),
    domain_sequence bigint NOT NULL CHECK (domain_sequence > 0),
    ciphertext_byte_count bigint NOT NULL CHECK (ciphertext_byte_count >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,domain_id,message_id),
    FOREIGN KEY (tenant_id,domain_id) REFERENCES relay_domains(tenant_id,domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,domain_id,fence_id) REFERENCES relay_checkpoint_fences(tenant_id,domain_id,fence_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id,domain_id,publisher_member_id) REFERENCES relay_members(tenant_id,domain_id,member_id) DEFERRABLE INITIALLY DEFERRED
);
