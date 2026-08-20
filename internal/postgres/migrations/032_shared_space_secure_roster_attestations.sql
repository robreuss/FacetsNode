ALTER TABLE shared_spaces
    ADD COLUMN secure_roster_attestation jsonb;

ALTER TABLE shared_space_participant_role_changes
    ADD COLUMN secure_roster_attestation jsonb;

ALTER TABLE shared_space_participant_revocations
    ADD COLUMN secure_roster_attestation jsonb;
