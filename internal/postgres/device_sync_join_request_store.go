package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func (s *RelayStore) CreateJoinRequest(
	ctx context.Context,
	request devicesync.JoinRequest,
	nowMilliseconds int64,
) (devicesync.JoinRequestCreateResult, error) {
	if err := request.Validate(); err != nil {
		return devicesync.JoinRequestCreateResult{}, err
	}
	if err := request.RequireActive(nowMilliseconds); err != nil {
		return devicesync.JoinRequestCreateResult{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return devicesync.JoinRequestCreateResult{}, fmt.Errorf("begin Device Sync join request: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if existing, found, err := loadDeviceSyncJoinRequestForCreate(ctx, tx, request.RequestID, request.RetryID); err != nil {
		return devicesync.JoinRequestCreateResult{}, err
	} else if found {
		if existing == request {
			return devicesync.JoinRequestCreateResult{
				Acceptance: relay.AcceptanceDuplicate, RequestID: existing.RequestID,
				ExpiresAtMilliseconds: existing.ExpiresAtMilliseconds,
			}, nil
		}
		return devicesync.JoinRequestCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeJoinRequestCollision, "join request ID or retry ID was reused",
		)
	}
	var collision bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM device_sync_join_requests
			WHERE pin_authorization_digest=$1 AND expires_at_milliseconds>$2
		)
	`, request.PINAuthorizationDigest, nowMilliseconds).Scan(&collision); err != nil {
		return devicesync.JoinRequestCreateResult{}, fmt.Errorf("check Device Sync join request PIN: %w", err)
	}
	if collision {
		return devicesync.JoinRequestCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeJoinRequestCollision, "join request PIN is already active",
		)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_sync_join_requests (
			request_id,retry_id,version,candidate_device_id,candidate_bootstrap_public_key,
			polling_authorization_digest,pin_authorization_digest,created_at_milliseconds,
			expires_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, request.RequestID, request.RetryID, request.Version, request.CandidateDeviceID,
		request.CandidateBootstrapPublicKey, request.PollingAuthorizationDigest,
		request.PINAuthorizationDigest, request.CreatedAtMilliseconds, request.ExpiresAtMilliseconds); err != nil {
		return devicesync.JoinRequestCreateResult{}, fmt.Errorf("insert Device Sync join request: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return devicesync.JoinRequestCreateResult{}, fmt.Errorf("commit Device Sync join request: %w", err)
	}
	return devicesync.JoinRequestCreateResult{
		Acceptance: relay.AcceptanceAccepted, RequestID: request.RequestID,
		ExpiresAtMilliseconds: request.ExpiresAtMilliseconds,
	}, nil
}

func (s *RelayStore) LookupJoinRequest(
	ctx context.Context,
	credential relay.AdministrationCredential,
	pin string,
	nowMilliseconds int64,
) (devicesync.JoinRequestSponsorPresentation, error) {
	digest, err := devicesync.JoinRequestPINAuthorizationDigest(pin)
	if err != nil {
		return devicesync.JoinRequestSponsorPresentation{}, devicesync.NewProtocolError(
			devicesync.CodeInvalidJoinRequest, err.Error(),
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return devicesync.JoinRequestSponsorPresentation{}, fmt.Errorf("begin Device Sync join lookup: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := authorizeDeviceSyncControlDomain(ctx, tx, credential, "FOR SHARE"); err != nil {
		return devicesync.JoinRequestSponsorPresentation{}, err
	}
	request, found, err := loadDeviceSyncJoinRequestByPINDigest(ctx, tx, digest, nowMilliseconds, "")
	if err != nil {
		return devicesync.JoinRequestSponsorPresentation{}, err
	}
	if !found {
		return devicesync.JoinRequestSponsorPresentation{}, devicesync.NewProtocolError(
			devicesync.CodeJoinRequestNotFound, "join request was not found",
		)
	}
	if request.PrincipalID != nil && *request.PrincipalID != credential.TenantID {
		return devicesync.JoinRequestSponsorPresentation{}, devicesync.NewProtocolError(
			devicesync.CodeWrongScope, "join request already belongs to another Device Sync principal",
		)
	}
	if err := tx.Commit(ctx); err != nil {
		return devicesync.JoinRequestSponsorPresentation{}, fmt.Errorf("commit Device Sync join lookup: %w", err)
	}
	return deviceSyncJoinRequestSponsorPresentation(request), nil
}

func (s *RelayStore) StoreJoinRequestBootstrap(
	ctx context.Context,
	credential relay.AdministrationCredential,
	bootstrap devicesync.JoinBootstrapEnvelope,
	nowMilliseconds int64,
) (relay.Acceptance, error) {
	if err := bootstrap.Validate(); err != nil {
		return "", err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", fmt.Errorf("begin Device Sync join bootstrap: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := authorizeDeviceSyncControlDomain(ctx, tx, credential, "FOR UPDATE"); err != nil {
		return "", err
	}
	request, found, err := loadDeviceSyncJoinRequestForWrite(ctx, tx, bootstrap.RequestID, uuid.Nil)
	if err != nil {
		return "", err
	}
	if !found {
		return "", devicesync.NewProtocolError(devicesync.CodeJoinRequestNotFound, "join request was not found")
	}
	if err := request.RequireActive(nowMilliseconds); err != nil {
		return "", err
	}
	if bootstrap.ExpiresAtMilliseconds > request.ExpiresAtMilliseconds {
		return "", devicesync.NewProtocolError(devicesync.CodeWrongScope, "join request bootstrap outlives request")
	}
	if request.PrincipalID != nil || request.Bootstrap != nil {
		if request.PrincipalID != nil && *request.PrincipalID == credential.TenantID &&
			request.Bootstrap != nil && *request.Bootstrap == bootstrap {
			return relay.AcceptanceDuplicate, nil
		}
		return "", devicesync.NewProtocolError(devicesync.CodeJoinRequestClaimed, "join request already has a bootstrap")
	}
	payload, err := json.Marshal(bootstrap)
	if err != nil {
		return "", fmt.Errorf("encode Device Sync join bootstrap: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE device_sync_join_requests
		SET principal_id=$2,bootstrap=$3
		WHERE request_id=$1
	`, bootstrap.RequestID, credential.TenantID, payload); err != nil {
		return "", fmt.Errorf("store Device Sync join bootstrap: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit Device Sync join bootstrap: %w", err)
	}
	return relay.AcceptanceAccepted, nil
}

func (s *RelayStore) FetchJoinRequestBootstrap(
	ctx context.Context,
	credential devicesync.JoinRequestCredential,
	nowMilliseconds int64,
) (devicesync.JoinBootstrapEnvelope, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return devicesync.JoinBootstrapEnvelope{}, fmt.Errorf("begin Device Sync join bootstrap fetch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	request, found, err := loadDeviceSyncJoinRequestForRead(ctx, tx, credential.RequestID)
	if err != nil {
		return devicesync.JoinBootstrapEnvelope{}, err
	}
	if !found {
		return devicesync.JoinBootstrapEnvelope{}, devicesync.NewProtocolError(
			devicesync.CodeJoinRequestNotFound, "join request was not found",
		)
	}
	if err := request.VerifyPollingCredential(credential); err != nil {
		return devicesync.JoinBootstrapEnvelope{}, err
	}
	if err := request.RequireActive(nowMilliseconds); err != nil {
		return devicesync.JoinBootstrapEnvelope{}, err
	}
	if request.Bootstrap == nil {
		return devicesync.JoinBootstrapEnvelope{}, devicesync.NewProtocolError(
			devicesync.CodeJoinRequestNotFound, "join request bootstrap is not available",
		)
	}
	if err := tx.Commit(ctx); err != nil {
		return devicesync.JoinBootstrapEnvelope{}, fmt.Errorf("commit Device Sync join bootstrap fetch: %w", err)
	}
	return *request.Bootstrap, nil
}

func authorizeDeviceSyncControlDomain(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.AdministrationCredential,
	lock string,
) error {
	principal, err := loadDeviceSyncPrincipalAuthority(ctx, tx, credential.TenantID, lock)
	if err != nil {
		return err
	}
	if credential.DomainID != principal.controlDomainID {
		return devicesync.NewProtocolError(devicesync.CodeWrongScope, "join request requires the principal control domain")
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, lock)
	if err != nil {
		return err
	}
	return domain.Authorize(credential)
}

func loadDeviceSyncJoinRequestForWrite(
	ctx context.Context,
	tx pgx.Tx,
	requestID uuid.UUID,
	retryID uuid.UUID,
) (devicesync.JoinRequest, bool, error) {
	if requestID != uuid.Nil {
		request, found, err := loadDeviceSyncJoinRequest(ctx, tx, `WHERE request_id=$1 FOR UPDATE`, requestID)
		return request, found, err
	}
	return loadDeviceSyncJoinRequest(ctx, tx, `WHERE retry_id=$1 FOR UPDATE`, retryID)
}

func loadDeviceSyncJoinRequestForCreate(
	ctx context.Context,
	tx pgx.Tx,
	requestID uuid.UUID,
	retryID uuid.UUID,
) (devicesync.JoinRequest, bool, error) {
	return loadDeviceSyncJoinRequest(
		ctx,
		tx,
		`WHERE request_id=$1 OR retry_id=$2 ORDER BY request_id=$1 DESC FOR UPDATE`,
		requestID,
		retryID,
	)
}

func loadDeviceSyncJoinRequestForRead(ctx context.Context, tx pgx.Tx, requestID uuid.UUID) (devicesync.JoinRequest, bool, error) {
	return loadDeviceSyncJoinRequest(ctx, tx, `WHERE request_id=$1`, requestID)
}

func loadDeviceSyncJoinRequestByPINDigest(
	ctx context.Context,
	tx pgx.Tx,
	pinDigest string,
	nowMilliseconds int64,
	lock string,
) (devicesync.JoinRequest, bool, error) {
	query := `WHERE pin_authorization_digest=$1 AND expires_at_milliseconds>$2 ORDER BY created_at_milliseconds DESC LIMIT 1`
	if lock != "" {
		query += " " + lock
	}
	return loadDeviceSyncJoinRequest(ctx, tx, query, pinDigest, nowMilliseconds)
}

func loadDeviceSyncJoinRequest(ctx context.Context, tx pgx.Tx, suffix string, arguments ...any) (devicesync.JoinRequest, bool, error) {
	var request devicesync.JoinRequest
	var principalID *uuid.UUID
	var bootstrapBytes []byte
	err := tx.QueryRow(ctx, `
		SELECT version,retry_id,request_id,candidate_device_id,candidate_bootstrap_public_key,
			polling_authorization_digest,pin_authorization_digest,created_at_milliseconds,
			expires_at_milliseconds,principal_id,bootstrap
		FROM device_sync_join_requests `+suffix,
		arguments...,
	).Scan(
		&request.Version, &request.RetryID, &request.RequestID, &request.CandidateDeviceID,
		&request.CandidateBootstrapPublicKey, &request.PollingAuthorizationDigest,
		&request.PINAuthorizationDigest, &request.CreatedAtMilliseconds, &request.ExpiresAtMilliseconds,
		&principalID, &bootstrapBytes,
	)
	if err == pgx.ErrNoRows {
		return devicesync.JoinRequest{}, false, nil
	}
	if err != nil {
		return devicesync.JoinRequest{}, false, fmt.Errorf("load Device Sync join request: %w", err)
	}
	request.PrincipalID = principalID
	if len(bootstrapBytes) > 0 {
		var bootstrap devicesync.JoinBootstrapEnvelope
		if err := json.Unmarshal(bootstrapBytes, &bootstrap); err != nil {
			return devicesync.JoinRequest{}, false, fmt.Errorf("decode Device Sync join bootstrap: %w", err)
		}
		request.Bootstrap = &bootstrap
	}
	if err := request.Validate(); err != nil {
		return devicesync.JoinRequest{}, false, err
	}
	return request, true, nil
}

func deviceSyncJoinRequestSponsorPresentation(request devicesync.JoinRequest) devicesync.JoinRequestSponsorPresentation {
	return devicesync.JoinRequestSponsorPresentation{
		Version: request.Version, RequestID: request.RequestID,
		CandidateDeviceID:           request.CandidateDeviceID,
		CandidateBootstrapPublicKey: request.CandidateBootstrapPublicKey,
		ExpiresAtMilliseconds:       request.ExpiresAtMilliseconds,
	}
}
