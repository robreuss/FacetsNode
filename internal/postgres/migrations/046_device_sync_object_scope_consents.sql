-- Isolated Sync-side decisions. No neutral binding, object, or publication is
-- created by these records. Bearer credentials and content keys are never stored.
CREATE TABLE device_sync_object_scope_clocks (
    principal_id uuid PRIMARY KEY REFERENCES device_sync_principals(principal_id) ON DELETE CASCADE,
    observed_at_ms bigint NOT NULL CHECK (observed_at_ms >= 0)
);

CREATE TABLE device_sync_object_scope_consents (
    principal_id uuid NOT NULL,
    space_id uuid NOT NULL,
    reference_digest text NOT NULL CHECK (reference_digest ~ '^[0-9a-f]{64}$'),
    binding_id uuid NOT NULL,
    link_id uuid NOT NULL,
    link_intent_digest text NOT NULL CHECK (link_intent_digest ~ '^[0-9a-f]{64}$'),
    canonical_consent bytea NOT NULL CHECK (octet_length(canonical_consent) BETWEEN 1 AND 4096),
    accepted_at_ms bigint NOT NULL CHECK (accepted_at_ms >= 0),
    withdrawn_at_ms bigint CHECK (withdrawn_at_ms >= accepted_at_ms),
    PRIMARY KEY (principal_id, reference_digest),
    UNIQUE (principal_id, binding_id),
    UNIQUE (principal_id, link_id),
    UNIQUE (principal_id, link_intent_digest),
    FOREIGN KEY (principal_id) REFERENCES device_sync_object_scope_clocks(principal_id),
    FOREIGN KEY (principal_id, space_id) REFERENCES device_sync_spaces(principal_id, space_id) ON DELETE CASCADE
);

CREATE CONSTRAINT TRIGGER ds_writable_device_sync_object_scope_clocks
AFTER INSERT OR UPDATE OR DELETE ON device_sync_object_scope_clocks
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION enforce_device_sync_scope_writable_mutation('principal_id');

CREATE CONSTRAINT TRIGGER ds_writable_device_sync_object_scope_consents
AFTER INSERT OR UPDATE OR DELETE ON device_sync_object_scope_consents
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION enforce_device_sync_scope_writable_mutation('principal_id');

CREATE TABLE device_sync_object_scope_mutations (
    principal_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    reference_digest text NOT NULL,
    canonical_mutation bytea NOT NULL CHECK (octet_length(canonical_mutation) BETWEEN 1 AND 4096),
    participant_device_id uuid NOT NULL,
    control_subscription_id uuid NOT NULL,
    space_subscription_id uuid NOT NULL,
    applied_at_ms bigint NOT NULL CHECK (applied_at_ms >= 0),
    PRIMARY KEY (principal_id, retry_id),
    FOREIGN KEY (principal_id, reference_digest) REFERENCES device_sync_object_scope_consents(principal_id, reference_digest) ON DELETE CASCADE
);

CREATE CONSTRAINT TRIGGER ds_writable_device_sync_object_scope_mutations
AFTER INSERT OR UPDATE OR DELETE ON device_sync_object_scope_mutations
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION enforce_device_sync_scope_writable_mutation('principal_id');
