package boxcontrol

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *PostgresStore) PinOwnerApprovedParticipant(
	ctx context.Context,
	enrollment BoxParticipantEnrollment,
	nowMilliseconds int64,
) error {
	if !enrollment.validInitialAt(nowMilliseconds) {
		return ErrParticipantAuthority
	}
	rootRecord, err := json.Marshal(enrollment.RootRecord)
	if err != nil || len(rootRecord) > 131072 {
		return ErrParticipantAuthority
	}
	grantRecord, err := json.Marshal(enrollment.GrantRecord)
	if err != nil || len(grantRecord) > 131072 {
		return ErrParticipantAuthority
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `
		INSERT INTO box_participants
			(participant_id, box_id, box_scoped_principal_id, root_key_fingerprint,
			 approved_at_milliseconds, revoked_at_milliseconds, root_record)
		SELECT $1, $2, $3, $4, $5, 0, $6 FROM box_state
		WHERE box_id = $2 AND owner_verifier <> ''
		ON CONFLICT DO NOTHING`,
		enrollment.Anchor.ParticipantID, enrollment.Anchor.BoxID,
		enrollment.Anchor.BoxScopedPrincipalID, enrollment.Anchor.RootKeyFingerprint,
		enrollment.Anchor.ApprovedAtMilliseconds, rootRecord)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		existing, readErr := readPinnedParticipant(tx.QueryRow(ctx, pinnedParticipantQuery,
			enrollment.Anchor.BoxID, enrollment.Anchor.ParticipantID, enrollment.Device.DeviceID))
		if readErr != nil || !sameParticipantEnrollment(existing, enrollment) {
			return ErrParticipantAuthority
		}
		return nil // exact retry; the original transaction already committed
	}
	result, err = tx.Exec(ctx, `
		INSERT INTO box_participant_devices
			(device_id, participant_id, grant_id, device_generation,
			 signing_key_fingerprint, revoked_through_generation, grant_record)
		VALUES ($1, $2, $3, $4, $5, 0, $6)
		ON CONFLICT DO NOTHING`,
		enrollment.Device.DeviceID, enrollment.Device.ParticipantID,
		enrollment.Device.GrantID, enrollment.Device.DeviceGeneration,
		enrollment.Device.SigningKeyFingerprint, grantRecord)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrParticipantAuthority
	}
	return tx.Commit(ctx)
}

const pinnedParticipantQuery = `
	SELECT p.box_id, p.participant_id, p.box_scoped_principal_id,
	       p.root_key_fingerprint, p.approved_at_milliseconds, p.revoked_at_milliseconds,
	       p.root_record, d.participant_id, d.device_id, d.grant_id,
	       d.device_generation, d.signing_key_fingerprint,
	       d.revoked_through_generation, d.grant_record
	FROM box_participants p
	JOIN box_state s ON s.box_id = p.box_id AND s.owner_verifier <> ''
	JOIN box_participant_devices d ON d.participant_id = p.participant_id
	WHERE p.box_id = $1 AND p.participant_id = $2 AND d.device_id = $3`

type participantRow interface {
	Scan(...any) error
}

func readPinnedParticipant(row participantRow) (BoxParticipantEnrollment, error) {
	var result BoxParticipantEnrollment
	var rootBytes, grantBytes []byte
	var deviceGeneration, revokedThrough int64
	err := row.Scan(&result.Anchor.BoxID, &result.Anchor.ParticipantID,
		&result.Anchor.BoxScopedPrincipalID, &result.Anchor.RootKeyFingerprint,
		&result.Anchor.ApprovedAtMilliseconds, &result.Anchor.RevokedAtMilliseconds,
		&rootBytes, &result.Device.ParticipantID, &result.Device.DeviceID,
		&result.Device.GrantID, &deviceGeneration, &result.Device.SigningKeyFingerprint,
		&revokedThrough, &grantBytes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return BoxParticipantEnrollment{}, ErrParticipantAuthority
		}
		return BoxParticipantEnrollment{}, err
	}
	if deviceGeneration < 0 || revokedThrough < 0 ||
		json.Unmarshal(rootBytes, &result.RootRecord) != nil ||
		json.Unmarshal(grantBytes, &result.GrantRecord) != nil {
		return BoxParticipantEnrollment{}, ErrParticipantAuthority
	}
	result.Device.DeviceGeneration = uint64(deviceGeneration)
	result.Device.RevokedThroughGeneration = uint64(revokedThrough)
	return result, nil
}

func (store *PostgresStore) PinnedParticipant(
	ctx context.Context,
	boxID, participantID, deviceID uuid.UUID,
) (BoxParticipantEnrollment, error) {
	return readPinnedParticipant(store.pool.QueryRow(ctx, pinnedParticipantQuery,
		boxID, participantID, deviceID))
}
