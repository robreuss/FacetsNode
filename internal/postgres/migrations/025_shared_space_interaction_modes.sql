ALTER TABLE shared_spaces
    ADD COLUMN interaction_mode text NOT NULL
        CHECK (interaction_mode IN ('broadcast', 'community', 'collaborative'));
