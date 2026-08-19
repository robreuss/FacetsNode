CREATE TABLE shared_space_participant_presentations (
    space_id uuid NOT NULL,
    participant_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    retry_id uuid NOT NULL UNIQUE,
    version smallint NOT NULL CHECK (version = 1),
    request_payload jsonb NOT NULL,
    display_name text NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 512),
    updated_at_milliseconds bigint NOT NULL CHECK (updated_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, participant_id, revision),
    FOREIGN KEY (space_id, participant_id)
        REFERENCES shared_space_participants(space_id, participant_id) ON DELETE CASCADE
);

CREATE INDEX shared_space_participant_presentations_latest_idx
    ON shared_space_participant_presentations (space_id, participant_id, revision DESC);
