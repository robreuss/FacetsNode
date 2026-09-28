package boxcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *PostgresStore) CreateParticipantEnrollmentRequest(ctx context.Context, request BoxParticipantEnrollmentRequest, now int64) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var deviceName string
	err = tx.QueryRow(ctx, `SELECT g.device_name FROM connection_grants g
		JOIN box_state s ON s.box_id = $2 AND s.owner_verifier <> ''
		WHERE g.grant_id = $1 AND g.revoked_at IS NULL AND g.expires_at > $3 FOR UPDATE OF g, s`,
		request.ConnectionGrantID, request.Enrollment.Anchor.BoxID, time.UnixMilli(now)).Scan(&deviceName)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrParticipantAuthority
	}
	if err != nil {
		return err
	}
	request.ConnectionDeviceName = deviceName
	existing, readErr := readParticipantRequest(tx.QueryRow(ctx, participantRequestSelect+` WHERE r.request_id = $1`, request.RequestID))
	if readErr == nil {
		if !sameParticipantRequestCore(existing, request) {
			return ErrParticipantAuthority
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(readErr, ErrParticipantAuthority) {
		return readErr
	}
	var boxPending, connectionPending int
	err = tx.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE connection_grant_id = $2)
		FROM box_participant_enrollment_requests WHERE box_id = $1
		AND decision = 'pending' AND expires_at_milliseconds > $3`,
		request.Enrollment.Anchor.BoxID, request.ConnectionGrantID, now).Scan(&boxPending, &connectionPending)
	if err != nil {
		return err
	}
	if boxPending >= maximumPendingParticipantRequests || connectionPending >= maximumPendingRequestsPerConnection {
		return ErrParticipantAuthority
	}
	if !request.validSubmissionAt(now) {
		return ErrParticipantAuthority
	}
	proposal, err := json.Marshal(request)
	if err != nil || len(proposal) > 32768 {
		return ErrParticipantAuthority
	}
	result, err := tx.Exec(ctx, `INSERT INTO box_participant_enrollment_requests
		(request_id, box_id, connection_grant_id, participant_id, device_id, proposal,
		 requested_at_milliseconds, expires_at_milliseconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
		request.RequestID, request.Enrollment.Anchor.BoxID, request.ConnectionGrantID,
		request.Enrollment.Anchor.ParticipantID, request.Enrollment.Device.DeviceID,
		proposal, request.RequestedAtMillis, request.ExpiresAtMillis)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		existing, readErr = readParticipantRequest(tx.QueryRow(ctx, participantRequestSelect+` WHERE r.request_id = $1`, request.RequestID))
		if readErr != nil || !sameParticipantRequestCore(existing, request) {
			return ErrParticipantAuthority
		}
	}
	return tx.Commit(ctx)
}

const participantRequestSelect = `SELECT r.request_id, r.connection_grant_id, g.device_name,
	 r.proposal, r.requested_at_milliseconds, r.expires_at_milliseconds,
	 r.decision, r.decided_at_milliseconds
	 FROM box_participant_enrollment_requests r
	 JOIN connection_grants g ON g.grant_id = r.connection_grant_id`

func readParticipantRequest(row participantRow) (BoxParticipantEnrollmentRequest, error) {
	var request BoxParticipantEnrollmentRequest
	var proposal []byte
	err := row.Scan(&request.RequestID, &request.ConnectionGrantID, &request.ConnectionDeviceName,
		&proposal, &request.RequestedAtMillis, &request.ExpiresAtMillis,
		&request.Decision, &request.DecidedAtMilliseconds)
	if errors.Is(err, pgx.ErrNoRows) {
		return BoxParticipantEnrollmentRequest{}, ErrParticipantAuthority
	}
	if err != nil {
		return BoxParticipantEnrollmentRequest{}, err
	}
	var body struct {
		Enrollment   BoxParticipantEnrollment   `json:"enrollment"`
		Presentation BoxParticipantPresentation `json:"presentation"`
		Proof        BoxSignedParticipantProof  `json:"proof"`
	}
	if json.Unmarshal(proposal, &body) != nil {
		return BoxParticipantEnrollmentRequest{}, ErrParticipantAuthority
	}
	request.Enrollment, request.Presentation, request.Proof = body.Enrollment, body.Presentation, body.Proof
	return request, nil
}

func (store *PostgresStore) ParticipantEnrollmentRequest(ctx context.Context, requestID, grantID uuid.UUID, now int64) (BoxParticipantEnrollmentRequest, error) {
	request, err := readParticipantRequest(store.pool.QueryRow(ctx, participantRequestSelect+`
		WHERE r.request_id = $1 AND r.connection_grant_id = $2
		  AND g.revoked_at IS NULL AND g.expires_at > $3`, requestID, grantID, time.UnixMilli(now)))
	if err != nil {
		return BoxParticipantEnrollmentRequest{}, err
	}
	if request.Decision == "pending" && now >= request.ExpiresAtMillis {
		request.Decision = "expired"
	}
	return request, nil
}

func (store *PostgresStore) PendingParticipantEnrollmentRequests(ctx context.Context, boxID uuid.UUID, now int64) ([]BoxParticipantEnrollmentRequest, error) {
	rows, err := store.pool.Query(ctx, participantRequestSelect+`
		JOIN box_state s ON s.box_id = r.box_id AND s.owner_verifier <> ''
		WHERE r.box_id = $1 AND r.decision = 'pending' AND r.expires_at_milliseconds > $2
		  AND g.revoked_at IS NULL AND g.expires_at > $3
		ORDER BY r.requested_at_milliseconds, r.request_id LIMIT 256`, boxID, now, time.UnixMilli(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := make([]BoxParticipantEnrollmentRequest, 0)
	for rows.Next() {
		request, readErr := readParticipantRequest(rows)
		if readErr != nil {
			return nil, readErr
		}
		results = append(results, request)
	}
	return results, rows.Err()
}

func (store *PostgresStore) DecideParticipantEnrollmentRequest(ctx context.Context, boxID, requestID uuid.UUID, approve bool, now int64) error {
	if boxID == uuid.Nil || requestID == uuid.Nil || now <= 0 {
		return ErrParticipantAuthority
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	request, err := readParticipantRequest(tx.QueryRow(ctx, participantRequestSelect+`
		JOIN box_state s ON s.box_id = r.box_id AND s.owner_verifier <> ''
		WHERE r.request_id = $1 AND r.box_id = $2 AND r.decision = 'pending'
		  AND r.expires_at_milliseconds > $3
		  AND g.revoked_at IS NULL AND g.expires_at > $4 FOR UPDATE OF r, g`,
		requestID, boxID, now, time.UnixMilli(now)))
	if err != nil {
		return err
	}
	decision := "rejected"
	if approve {
		request.Enrollment.Anchor.ApprovedAtMilliseconds = now
		if !request.Enrollment.validInitialAt(now) {
			return ErrParticipantAuthority
		}
		rootRecord, rootErr := json.Marshal(request.Enrollment.RootRecord)
		grantRecord, grantErr := json.Marshal(request.Enrollment.GrantRecord)
		if rootErr != nil || grantErr != nil || len(rootRecord) > 131072 || len(grantRecord) > 131072 {
			return ErrParticipantAuthority
		}
		if err := insertPinnedParticipant(ctx, tx, request.Enrollment, rootRecord, grantRecord); err != nil {
			return err
		}
		decision = "approved"
	}
	_, err = tx.Exec(ctx, `UPDATE box_participant_enrollment_requests
		SET decision = $2, decided_at_milliseconds = $3 WHERE request_id = $1`, requestID, decision, now)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
