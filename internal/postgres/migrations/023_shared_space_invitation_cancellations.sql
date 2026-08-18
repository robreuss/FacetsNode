CREATE TABLE shared_space_invitation_cancellations (
    space_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    version smallint NOT NULL,
    cancelled_at_milliseconds bigint NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, retry_id),
    UNIQUE (space_id, invitation_id),
    FOREIGN KEY (space_id, invitation_id)
        REFERENCES shared_space_invitations (space_id, invitation_id)
        ON DELETE CASCADE,
    CHECK (version = 1),
    CHECK (cancelled_at_milliseconds >= 0)
);
