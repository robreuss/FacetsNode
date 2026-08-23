CREATE TABLE shared_space_compute_bindings (
    space_id uuid NOT NULL REFERENCES shared_spaces(space_id) ON DELETE CASCADE,
    binding_id uuid NOT NULL,
    pool_id uuid NOT NULL,
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    binding_payload jsonb NOT NULL,
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    updated_at_milliseconds bigint NOT NULL CHECK (updated_at_milliseconds >= created_at_milliseconds),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, binding_id)
);

CREATE TABLE shared_space_compute_binding_changes (
    space_id uuid NOT NULL REFERENCES shared_spaces(space_id) ON DELETE CASCADE,
    retry_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    pool_id uuid NOT NULL,
    request_payload jsonb NOT NULL,
    response_payload jsonb NOT NULL,
    changed_at_milliseconds bigint NOT NULL CHECK (changed_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, retry_id),
    FOREIGN KEY (space_id, binding_id)
        REFERENCES shared_space_compute_bindings(space_id, binding_id) ON DELETE CASCADE
);

ALTER TABLE shared_space_authority_events
    ADD COLUMN compute_binding_id uuid,
    ADD COLUMN compute_pool_id uuid,
    ADD COLUMN previous_binding_revision bigint CHECK (previous_binding_revision >= 0),
    ADD COLUMN current_binding_revision bigint CHECK (current_binding_revision > 0);

ALTER TABLE shared_space_authority_events
    DROP CONSTRAINT shared_space_authority_events_event_type_check;

ALTER TABLE shared_space_authority_events
    ADD CONSTRAINT shared_space_authority_events_event_type_check CHECK (event_type IN (
        'space_provisioned',
        'invitation_created',
        'invitation_claimed',
        'invitation_cancelled',
        'participant_role_changed',
        'participant_revoked',
        'space_compute_binding_changed'
    ));

CREATE INDEX shared_space_compute_binding_changes_binding_idx
    ON shared_space_compute_binding_changes (space_id, binding_id, changed_at_milliseconds);

CREATE INDEX shared_space_compute_bindings_pool_idx
    ON shared_space_compute_bindings (space_id, pool_id, binding_id);
