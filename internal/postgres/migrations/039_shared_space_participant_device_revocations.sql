CREATE TABLE shared_space_participant_device_revocations (
    space_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    participant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    request_payload jsonb NOT NULL,
    response_payload jsonb NOT NULL,
    revoked_at_milliseconds bigint NOT NULL CHECK (revoked_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, retry_id),
    UNIQUE (space_id, participant_id, device_id),
    FOREIGN KEY (space_id, participant_id, device_id)
        REFERENCES shared_space_participant_device_keys(space_id, participant_id, device_id)
        ON DELETE CASCADE
);

ALTER TABLE shared_space_authority_events
    DROP CONSTRAINT shared_space_authority_events_event_type_check;

ALTER TABLE shared_space_authority_events
    ADD CONSTRAINT shared_space_authority_events_event_type_check CHECK (event_type IN (
        'space_provisioned',
        'invitation_created',
        'invitation_claimed',
        'invitation_cancelled',
        'participant_role_changed',
        'participant_device_enrolled',
        'participant_device_revoked',
        'participant_revoked',
        'space_compute_binding_changed'
    ));
