-- Content-blind audit binding for Secure Shared Space membership transitions.
-- This digest identifies the signed roster attestation that authorized an
-- accepted transition; it is not a content or key-material field.
ALTER TABLE shared_space_authority_events
    ADD COLUMN secure_roster_digest text
        CHECK (secure_roster_digest IS NULL OR secure_roster_digest ~ '^[0-9a-f]{64}$');
