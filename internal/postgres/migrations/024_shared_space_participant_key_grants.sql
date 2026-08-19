CREATE TABLE shared_space_participant_key_grants (
    space_id uuid NOT NULL,
    key_epoch bigint NOT NULL CHECK (key_epoch > 0),
    participant_id uuid NOT NULL,
    issuer_participant_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    grant_payload jsonb NOT NULL,
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, key_epoch, participant_id),
    FOREIGN KEY (space_id, participant_id)
        REFERENCES shared_space_participants(space_id, participant_id)
        ON DELETE CASCADE,
    FOREIGN KEY (space_id, issuer_participant_id)
        REFERENCES shared_space_participants(space_id, participant_id)
        ON DELETE RESTRICT
);

CREATE INDEX shared_space_participant_key_grants_recipient_idx
    ON shared_space_participant_key_grants (space_id, participant_id, key_epoch DESC);
