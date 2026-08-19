CREATE TABLE shared_space_authority_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    space_id uuid NOT NULL REFERENCES shared_spaces(space_id) ON DELETE CASCADE,
    domain_id uuid NOT NULL,
    event_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    event_type text NOT NULL CHECK (event_type IN (
        'space_provisioned',
        'invitation_created',
        'invitation_claimed',
        'invitation_cancelled',
        'participant_role_changed',
        'participant_revoked'
    )),
    subject_participant_id uuid,
    invitation_id uuid,
    previous_role text CHECK (previous_role IN ('host', 'moderator', 'participant', 'reader')),
    current_role text CHECK (current_role IN ('host', 'moderator', 'participant', 'reader')),
    previous_key_epoch bigint CHECK (previous_key_epoch > 0),
    current_key_epoch bigint CHECK (current_key_epoch > 0),
    occurred_at_milliseconds bigint NOT NULL CHECK (occurred_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (space_id, event_type, event_id),
    FOREIGN KEY (space_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE
);

CREATE INDEX shared_space_authority_events_space_sequence_idx
    ON shared_space_authority_events (space_id, sequence);
