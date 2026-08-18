package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func (s *RelayStore) CreateAccountAdmission(
	ctx context.Context,
	admission devicesync.AccountAdmission,
	nowMilliseconds int64,
) (devicesync.AdmissionCreateResult, error) {
	if err := admission.Validate(); err != nil {
		return devicesync.AdmissionCreateResult{}, err
	}
	if nowMilliseconds < admission.CreatedAtMilliseconds || nowMilliseconds >= admission.ExpiresAtMilliseconds ||
		admission.ClaimedAtMilliseconds != nil {
		return devicesync.AdmissionCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeInvalidAdmission, "account admission is not currently issuable",
		)
	}
	result, err := s.pool.Exec(ctx, `
		INSERT INTO device_sync_account_admissions (
			admission_id, retry_id, version, authorization_digest,
			created_at_milliseconds, expires_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT DO NOTHING
	`, admission.AdmissionID, admission.RetryID, admission.Version,
		admission.AuthorizationDigest, admission.CreatedAtMilliseconds,
		admission.ExpiresAtMilliseconds)
	if err != nil {
		return devicesync.AdmissionCreateResult{}, fmt.Errorf("insert Device Sync account admission: %w", err)
	}
	if result.RowsAffected() == 1 {
		return devicesync.AdmissionCreateResult{Acceptance: relay.AcceptanceAccepted, Admission: admission}, nil
	}
	existing, err := loadDeviceSyncAdmission(ctx, s.pool, admission.AdmissionID, admission.RetryID, "")
	if err != nil {
		return devicesync.AdmissionCreateResult{}, err
	}
	if existing == admission {
		return devicesync.AdmissionCreateResult{Acceptance: relay.AcceptanceDuplicate, Admission: existing}, nil
	}
	return devicesync.AdmissionCreateResult{}, devicesync.NewProtocolError(
		devicesync.CodeAdmissionCollision, "account admission ID or retry ID was reused",
	)
}

func (s *RelayStore) ClaimAccountAdmission(
	ctx context.Context,
	credential devicesync.AdmissionCredential,
	provisioning devicesync.PrincipalProvisioning,
	nowMilliseconds int64,
) (devicesync.PrincipalProvisioningResult, error) {
	if err := provisioning.Validate(); err != nil {
		return devicesync.PrincipalProvisioningResult{}, err
	}
	if provisioning.CreatedAtMilliseconds > nowMilliseconds {
		return devicesync.PrincipalProvisioningResult{}, devicesync.NewProtocolError(
			devicesync.CodeInvalidPrincipal, "principal starts in the future",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return devicesync.PrincipalProvisioningResult{}, fmt.Errorf("begin Device Sync principal provisioning: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	admission, err := loadDeviceSyncAdmission(ctx, tx, credential.AdmissionID, uuid.Nil, "FOR UPDATE")
	if err != nil {
		return devicesync.PrincipalProvisioningResult{}, err
	}
	if err := admission.VerifyCredential(credential); err != nil {
		return devicesync.PrincipalProvisioningResult{}, err
	}
	if admission.ClaimedAtMilliseconds != nil {
		exact, err := deviceSyncPrincipalProvisioningEqual(ctx, tx, admission.AdmissionID, provisioning)
		if err != nil {
			return devicesync.PrincipalProvisioningResult{}, err
		}
		if !exact {
			return devicesync.PrincipalProvisioningResult{}, devicesync.NewProtocolError(
				devicesync.CodeAdmissionClaimed, "account admission was already claimed",
			)
		}
		relayResult, err := s.provisionTenantTx(ctx, tx, provisioning.Tenant, provisioning.ControlDomain)
		if err != nil {
			return devicesync.PrincipalProvisioningResult{}, err
		}
		return deviceSyncPrincipalResult(provisioning, relayResult, relay.AcceptanceDuplicate), nil
	}
	if err := admission.RequireActive(nowMilliseconds); err != nil {
		return devicesync.PrincipalProvisioningResult{}, err
	}
	var principalExists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM device_sync_principals
			WHERE principal_id=$1 OR claim_retry_id=$2 OR tenant_id=$3
		)
	`, provisioning.PrincipalID, provisioning.RetryID, provisioning.Tenant.TenantID).Scan(&principalExists); err != nil {
		return devicesync.PrincipalProvisioningResult{}, fmt.Errorf("check Device Sync principal collision: %w", err)
	}
	if principalExists {
		return devicesync.PrincipalProvisioningResult{}, devicesync.NewProtocolError(
			devicesync.CodePrincipalCollision, "principal ID or retry ID was reused",
		)
	}
	relayResult, err := s.provisionTenantTx(ctx, tx, provisioning.Tenant, provisioning.ControlDomain)
	if err != nil {
		return devicesync.PrincipalProvisioningResult{}, err
	}
	if relayResult.Acceptance != relay.AcceptanceAccepted {
		return devicesync.PrincipalProvisioningResult{}, devicesync.NewProtocolError(
			devicesync.CodePrincipalCollision, "principal relay authority already exists",
		)
	}
	controlDomainID := provisioning.ControlDomain.Registration.DomainID
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_sync_principals (
			principal_id, claim_retry_id, account_admission_id, tenant_id,
			control_domain_id, initial_device_id, created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, provisioning.PrincipalID, provisioning.RetryID, admission.AdmissionID,
		provisioning.Tenant.TenantID, controlDomainID, provisioning.InitialDeviceID,
		provisioning.CreatedAtMilliseconds); err != nil {
		return devicesync.PrincipalProvisioningResult{}, fmt.Errorf("insert Device Sync principal: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_sync_devices (
			principal_id, device_id, tenant_id, control_domain_id,
			control_member_id, created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6)
	`, provisioning.PrincipalID, provisioning.InitialDeviceID,
		provisioning.Tenant.TenantID, controlDomainID, provisioning.InitialDeviceID,
		provisioning.CreatedAtMilliseconds); err != nil {
		return devicesync.PrincipalProvisioningResult{}, fmt.Errorf("insert initial Device Sync device: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE device_sync_account_admissions
		SET claimed_at_milliseconds=$2, claimed_principal_id=$3, updated_at=now()
		WHERE admission_id=$1
	`, admission.AdmissionID, nowMilliseconds, provisioning.PrincipalID); err != nil {
		return devicesync.PrincipalProvisioningResult{}, fmt.Errorf("claim Device Sync account admission: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return devicesync.PrincipalProvisioningResult{}, fmt.Errorf("commit Device Sync principal provisioning: %w", err)
	}
	return deviceSyncPrincipalResult(provisioning, relayResult, relay.AcceptanceAccepted), nil
}

func loadDeviceSyncAdmission(
	ctx context.Context,
	querier relayQuerier,
	admissionID uuid.UUID,
	retryID uuid.UUID,
	lock string,
) (devicesync.AccountAdmission, error) {
	var admission devicesync.AccountAdmission
	query := `
		SELECT version,retry_id,admission_id,authorization_digest,
			created_at_milliseconds,expires_at_milliseconds,
			claimed_at_milliseconds,claimed_principal_id
		FROM device_sync_account_admissions
		WHERE admission_id=$1`
	arguments := []any{admissionID}
	if retryID != uuid.Nil {
		query += ` OR retry_id=$2`
		arguments = append(arguments, retryID)
	}
	if lock != "" {
		query += " " + lock
	}
	err := querier.QueryRow(ctx, query, arguments...).Scan(
		&admission.Version, &admission.RetryID, &admission.AdmissionID,
		&admission.AuthorizationDigest, &admission.CreatedAtMilliseconds,
		&admission.ExpiresAtMilliseconds, &admission.ClaimedAtMilliseconds,
		&admission.ClaimedPrincipalID,
	)
	if err == pgx.ErrNoRows {
		return devicesync.AccountAdmission{}, devicesync.NewProtocolError(
			devicesync.CodeAdmissionNotFound, "account admission was not found",
		)
	}
	if err != nil {
		return devicesync.AccountAdmission{}, fmt.Errorf("load Device Sync account admission: %w", err)
	}
	return admission, nil
}

func deviceSyncPrincipalProvisioningEqual(
	ctx context.Context,
	tx pgx.Tx,
	admissionID uuid.UUID,
	provisioning devicesync.PrincipalProvisioning,
) (bool, error) {
	var principalID, retryID, tenantID, domainID, deviceID uuid.UUID
	var createdAt int64
	err := tx.QueryRow(ctx, `
		SELECT principal_id,claim_retry_id,tenant_id,control_domain_id,
			initial_device_id,created_at_milliseconds
		FROM device_sync_principals
		WHERE account_admission_id=$1
	`, admissionID).Scan(&principalID, &retryID, &tenantID, &domainID, &deviceID, &createdAt)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load Device Sync principal: %w", err)
	}
	return principalID == provisioning.PrincipalID && retryID == provisioning.RetryID &&
		tenantID == provisioning.Tenant.TenantID &&
		domainID == provisioning.ControlDomain.Registration.DomainID &&
		deviceID == provisioning.InitialDeviceID &&
		createdAt == provisioning.CreatedAtMilliseconds, nil
}

func deviceSyncPrincipalResult(
	provisioning devicesync.PrincipalProvisioning,
	relayResult relay.TenantProvisioningResult,
	acceptance relay.Acceptance,
) devicesync.PrincipalProvisioningResult {
	return devicesync.PrincipalProvisioningResult{
		Acceptance: acceptance, RetryID: provisioning.RetryID,
		PrincipalID: provisioning.PrincipalID, DeviceID: provisioning.InitialDeviceID,
		Relay: relayResult, CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
}
