CREATE TABLE shared_space_participant_role_changes (
    space_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    participant_id uuid NOT NULL,
    version smallint NOT NULL,
    previous_role text NOT NULL,
    next_role text NOT NULL,
    changed_at_milliseconds bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, retry_id),
    FOREIGN KEY (space_id, participant_id)
        REFERENCES shared_space_participants (space_id, participant_id)
        ON DELETE CASCADE,
    CHECK (version = 1),
    CHECK (previous_role IN ('moderator', 'participant', 'reader')),
    CHECK (next_role IN ('moderator', 'participant', 'reader')),
    CHECK (previous_role <> next_role),
    CHECK (changed_at_milliseconds >= 0)
);

CREATE INDEX shared_space_participant_role_changes_participant_idx
    ON shared_space_participant_role_changes (space_id, participant_id, changed_at_milliseconds);
