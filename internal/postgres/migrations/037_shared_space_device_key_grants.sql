ALTER TABLE shared_space_participant_key_grants
    DROP CONSTRAINT shared_space_participant_key_grants_pkey;

CREATE UNIQUE INDEX shared_space_participant_key_grants_device_recipient_idx
    ON shared_space_participant_key_grants (
        space_id,
        key_epoch,
        participant_id,
        ((grant_payload->>'recipientDeviceID')::uuid)
    );
