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

func (s *RelayStore) CreateDeviceAdmission(
	ctx context.Context,
	credential relay.AdministrationCredential,
	admission devicesync.DeviceAdmission,
	nowMilliseconds int64,
) (devicesync.DeviceAdmissionCreateResult, error) {
	if err := admission.Validate(); err != nil {
		return devicesync.DeviceAdmissionCreateResult{}, err
	}
	if admission.CreatedAtMilliseconds > nowMilliseconds ||
		admission.RelayAdmission.ExpiresAtMilliseconds <= nowMilliseconds {
		return devicesync.DeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeInvalidAdmission, "device admission is not currently issuable",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return devicesync.DeviceAdmissionCreateResult{}, fmt.Errorf("begin Device Sync device admission: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	principal, err := loadDeviceSyncPrincipalAuthority(ctx, tx, admission.PrincipalID, "FOR UPDATE")
	if err != nil {
		return devicesync.DeviceAdmissionCreateResult{}, err
	}
	if credential.TenantID != admission.PrincipalID ||
		credential.DomainID != principal.controlDomainID ||
		admission.RelayAdmission.TenantID != principal.tenantID ||
		admission.RelayAdmission.DomainID != principal.controlDomainID ||
		admission.SubscriptionID != principal.controlSubscriptionID {
		return devicesync.DeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeWrongScope, "device admission belongs to another principal control domain",
		)
	}

	existing, found, err := loadDeviceSyncDeviceAdmissionForCreation(ctx, tx, admission)
	if err != nil {
		return devicesync.DeviceAdmissionCreateResult{}, err
	}
	if found {
		if !deviceSyncDeviceAdmissionCreationEqual(existing, admission) {
			if existing.deviceID == admission.DeviceID {
				return devicesync.DeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
					devicesync.CodeDeviceCollision, "device already has another admission",
				)
			}
			return devicesync.DeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
				devicesync.CodeAdmissionCollision, "device admission ID or retry ID was reused",
			)
		}
		relayResult, err := s.createSubscriptionAdmissionTx(
			ctx, tx, credential, admission.SubscriptionID,
			admission.RelayAdmission, nowMilliseconds,
		)
		if err != nil {
			return devicesync.DeviceAdmissionCreateResult{}, err
		}
		return devicesync.DeviceAdmissionCreateResult{
			Acceptance: relayResult.Acceptance,
			Admission:  admission,
		}, nil
	}

	var registered bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM device_sync_devices
			WHERE principal_id=$1 AND device_id=$2
		)
	`, admission.PrincipalID, admission.DeviceID).Scan(&registered); err != nil {
		return devicesync.DeviceAdmissionCreateResult{}, fmt.Errorf("check Device Sync device collision: %w", err)
	}
	if registered {
		return devicesync.DeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeDeviceCollision, "device is already registered",
		)
	}

	relayResult, err := s.createSubscriptionAdmissionTx(
		ctx, tx, credential, admission.SubscriptionID,
		admission.RelayAdmission, nowMilliseconds,
	)
	if err != nil {
		return devicesync.DeviceAdmissionCreateResult{}, err
	}
	if relayResult.Acceptance != relay.AcceptanceAccepted {
		return devicesync.DeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeAdmissionCollision, "device relay admission already exists",
		)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_sync_device_admissions (
			principal_id,retry_id,device_id,control_domain_id,
			subscription_id,admission_id,version,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, admission.PrincipalID, admission.RetryID, admission.DeviceID,
		admission.RelayAdmission.DomainID, admission.SubscriptionID,
		admission.RelayAdmission.AdmissionID, admission.Version,
		admission.CreatedAtMilliseconds); err != nil {
		return devicesync.DeviceAdmissionCreateResult{}, fmt.Errorf("insert Device Sync device admission: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return devicesync.DeviceAdmissionCreateResult{}, fmt.Errorf("commit Device Sync device admission: %w", err)
	}
	return devicesync.DeviceAdmissionCreateResult{
		Acceptance: relay.AcceptanceAccepted,
		Admission:  admission,
	}, nil
}

func (s *RelayStore) ClaimDeviceAdmission(
	ctx context.Context,
	credential devicesync.DeviceAdmissionCredential,
	claim devicesync.DeviceAdmissionClaim,
	nowMilliseconds int64,
) (devicesync.DeviceAdmissionClaimResult, error) {
	if err := claim.Validate(); err != nil {
		return devicesync.DeviceAdmissionClaimResult{}, err
	}
	if claim.ClaimedAtMilliseconds != nowMilliseconds {
		return devicesync.DeviceAdmissionClaimResult{}, devicesync.NewProtocolError(
			devicesync.CodeInvalidAdmission, "device claim time differs from server time",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return devicesync.DeviceAdmissionClaimResult{}, fmt.Errorf("begin Device Sync device claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	record, err := loadDeviceSyncDeviceAdmissionForClaim(
		ctx, tx, credential.PrincipalID, credential.AdmissionID,
	)
	if err != nil {
		return devicesync.DeviceAdmissionClaimResult{}, err
	}
	if claim.PrincipalID != record.principalID || claim.DeviceID != record.deviceID {
		return devicesync.DeviceAdmissionClaimResult{}, devicesync.NewProtocolError(
			devicesync.CodeWrongScope, "device claim belongs to another admission",
		)
	}

	relayResult, err := s.claimSubscriptionAdmissionTx(
		ctx, tx,
		relay.AdmissionCredential{
			TenantID: record.principalID, DomainID: record.controlDomainID,
			AdmissionID: credential.AdmissionID, Token: credential.Token,
		},
		claim.RelayClaim,
		nowMilliseconds,
	)
	if err != nil {
		return devicesync.DeviceAdmissionClaimResult{}, err
	}
	if record.claimedAtMilliseconds != nil {
		if record.claimedMemberID == nil || *record.claimedMemberID != claim.DeviceID ||
			relayResult.Acceptance != relay.AcceptanceDuplicate {
			return devicesync.DeviceAdmissionClaimResult{}, devicesync.NewProtocolError(
				devicesync.CodeAdmissionClaimed, "device admission was already claimed",
			)
		}
		return deviceSyncDeviceClaimResult(claim, relayResult, relay.AcceptanceDuplicate), nil
	}

	var registered bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM device_sync_devices
			WHERE principal_id=$1 AND device_id=$2
		)
	`, claim.PrincipalID, claim.DeviceID).Scan(&registered); err != nil {
		return devicesync.DeviceAdmissionClaimResult{}, fmt.Errorf("check claimed Device Sync device: %w", err)
	}
	if registered {
		return devicesync.DeviceAdmissionClaimResult{}, devicesync.NewProtocolError(
			devicesync.CodeDeviceCollision, "device is already registered",
		)
	}
	if relayResult.Acceptance != relay.AcceptanceAccepted {
		return devicesync.DeviceAdmissionClaimResult{}, devicesync.NewProtocolError(
			devicesync.CodeAdmissionClaimed, "device relay admission was already claimed",
		)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_sync_devices (
			principal_id,device_id,tenant_id,control_domain_id,
			control_member_id,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6)
	`, claim.PrincipalID, claim.DeviceID, claim.PrincipalID,
		record.controlDomainID, relayResult.Member.MemberRegistration.MemberID,
		nowMilliseconds); err != nil {
		return devicesync.DeviceAdmissionClaimResult{}, fmt.Errorf("insert Device Sync device: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE device_sync_device_admissions
		SET claimed_at_milliseconds=$3,claimed_member_id=$4,updated_at=now()
		WHERE principal_id=$1 AND admission_id=$2
	`, claim.PrincipalID, credential.AdmissionID, nowMilliseconds,
		relayResult.Member.MemberRegistration.MemberID); err != nil {
		return devicesync.DeviceAdmissionClaimResult{}, fmt.Errorf("claim Device Sync device admission: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return devicesync.DeviceAdmissionClaimResult{}, fmt.Errorf("commit Device Sync device claim: %w", err)
	}
	return deviceSyncDeviceClaimResult(claim, relayResult, relay.AcceptanceAccepted), nil
}

func (s *RelayStore) ProvisionSpace(
	ctx context.Context,
	credential relay.TenantCredential,
	provisioning devicesync.SpaceProvisioning,
	nowMilliseconds int64,
) (devicesync.SpaceProvisioningResult, error) {
	if err := provisioning.Validate(); err != nil {
		return devicesync.SpaceProvisioningResult{}, err
	}
	if credential.TenantID != provisioning.PrincipalID ||
		provisioning.CreatedAtMilliseconds > nowMilliseconds {
		return devicesync.SpaceProvisioningResult{}, devicesync.NewProtocolError(
			devicesync.CodeWrongScope, "Device Sync Space belongs to another principal",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return devicesync.SpaceProvisioningResult{}, fmt.Errorf("begin Device Sync Space provisioning: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	principal, err := loadDeviceSyncPrincipalAuthority(ctx, tx, provisioning.PrincipalID, "FOR UPDATE")
	if err != nil {
		return devicesync.SpaceProvisioningResult{}, err
	}
	if principal.tenantID != credential.TenantID {
		return devicesync.SpaceProvisioningResult{}, devicesync.NewProtocolError(
			devicesync.CodeWrongScope, "Device Sync Space belongs to another relay tenant",
		)
	}
	var deviceExists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM device_sync_devices
			WHERE principal_id=$1 AND device_id=$2
		)
	`, provisioning.PrincipalID, provisioning.InitialDeviceID).Scan(&deviceExists); err != nil {
		return devicesync.SpaceProvisioningResult{}, fmt.Errorf("check initial Device Sync Space device: %w", err)
	}
	if !deviceExists {
		return devicesync.SpaceProvisioningResult{}, devicesync.NewProtocolError(
			devicesync.CodeUnauthorized, "initial Space device is not enrolled",
		)
	}

	existing, found, err := loadDeviceSyncSpaceForProvisioning(ctx, tx, provisioning)
	if err != nil {
		return devicesync.SpaceProvisioningResult{}, err
	}
	if found && !deviceSyncSpaceProvisioningEqual(existing, provisioning) {
		return devicesync.SpaceProvisioningResult{}, devicesync.NewProtocolError(
			devicesync.CodeSpaceCollision, "Device Sync Space ID, retry ID, or domain ID was reused",
		)
	}
	relayResult, err := s.provisionDomainTx(ctx, tx, credential, provisioning.Domain, nowMilliseconds)
	if err != nil {
		return devicesync.SpaceProvisioningResult{}, err
	}
	if found {
		if relayResult.Acceptance != relay.AcceptanceDuplicate {
			return devicesync.SpaceProvisioningResult{}, devicesync.NewProtocolError(
				devicesync.CodeSpaceCollision, "Device Sync Space binding differs from its relay domain",
			)
		}
		if err := tx.Commit(ctx); err != nil {
			return devicesync.SpaceProvisioningResult{}, fmt.Errorf("commit duplicate Device Sync Space provisioning: %w", err)
		}
		return deviceSyncSpaceResult(provisioning, relayResult, relay.AcceptanceDuplicate), nil
	}
	if relayResult.Acceptance != relay.AcceptanceAccepted {
		return devicesync.SpaceProvisioningResult{}, devicesync.NewProtocolError(
			devicesync.CodeSpaceCollision, "Space relay domain already exists without a Device Sync binding",
		)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_sync_spaces (
			principal_id,space_id,provisioning_retry_id,domain_id,
			subscription_id,initial_device_id,version,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, provisioning.PrincipalID, provisioning.SpaceID, provisioning.RetryID,
		provisioning.Domain.Registration.DomainID,
		provisioning.Domain.Subscription.SubscriptionID,
		provisioning.InitialDeviceID, provisioning.Version,
		provisioning.CreatedAtMilliseconds); err != nil {
		return devicesync.SpaceProvisioningResult{}, fmt.Errorf("insert Device Sync Space: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_sync_space_devices (
			principal_id,space_id,device_id,domain_id,subscription_id,
			member_id,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, provisioning.PrincipalID, provisioning.SpaceID,
		provisioning.InitialDeviceID, provisioning.Domain.Registration.DomainID,
		provisioning.Domain.Subscription.SubscriptionID,
		provisioning.Domain.InitialMember.MemberID,
		provisioning.CreatedAtMilliseconds); err != nil {
		return devicesync.SpaceProvisioningResult{}, fmt.Errorf("insert initial Device Sync Space device: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return devicesync.SpaceProvisioningResult{}, fmt.Errorf("commit Device Sync Space provisioning: %w", err)
	}
	return deviceSyncSpaceResult(provisioning, relayResult, relay.AcceptanceAccepted), nil
}

type deviceSyncPrincipalAuthority struct {
	tenantID              uuid.UUID
	controlDomainID       uuid.UUID
	controlSubscriptionID uuid.UUID
}

func loadDeviceSyncPrincipalAuthority(
	ctx context.Context,
	querier relayQuerier,
	principalID uuid.UUID,
	lock string,
) (deviceSyncPrincipalAuthority, error) {
	var authority deviceSyncPrincipalAuthority
	query := `
		SELECT p.tenant_id,p.control_domain_id,m.subscription_id
		FROM device_sync_principals p
		JOIN relay_members m
		  ON m.tenant_id=p.tenant_id AND m.domain_id=p.control_domain_id
		 AND m.member_id=p.initial_device_id
		JOIN relay_subscriptions s
		  ON s.tenant_id=m.tenant_id AND s.domain_id=m.domain_id
		 AND s.subscription_id=m.subscription_id
		WHERE p.principal_id=$1 AND s.status='active'`
	if lock != "" {
		query += " " + lock + " OF p"
	}
	err := querier.QueryRow(ctx, query, principalID).Scan(
		&authority.tenantID, &authority.controlDomainID,
		&authority.controlSubscriptionID,
	)
	if err == pgx.ErrNoRows {
		return deviceSyncPrincipalAuthority{}, devicesync.NewProtocolError(
			devicesync.CodeUnauthorized, "Device Sync principal was not found",
		)
	}
	if err != nil {
		return deviceSyncPrincipalAuthority{}, fmt.Errorf("load Device Sync principal authority: %w", err)
	}
	return authority, nil
}

type deviceSyncSpaceRecord struct {
	version               int
	retryID               uuid.UUID
	principalID           uuid.UUID
	spaceID               uuid.UUID
	domainID              uuid.UUID
	subscriptionID        uuid.UUID
	initialDeviceID       uuid.UUID
	createdAtMilliseconds int64
}

func loadDeviceSyncSpaceForProvisioning(
	ctx context.Context,
	tx pgx.Tx,
	provisioning devicesync.SpaceProvisioning,
) (deviceSyncSpaceRecord, bool, error) {
	var record deviceSyncSpaceRecord
	err := tx.QueryRow(ctx, `
		SELECT version,provisioning_retry_id,principal_id,space_id,domain_id,
			subscription_id,initial_device_id,created_at_milliseconds
		FROM device_sync_spaces
		WHERE principal_id=$1 AND (
			space_id=$2 OR provisioning_retry_id=$3 OR domain_id=$4
		)
		FOR UPDATE
	`, provisioning.PrincipalID, provisioning.SpaceID, provisioning.RetryID,
		provisioning.Domain.Registration.DomainID).Scan(
		&record.version, &record.retryID, &record.principalID, &record.spaceID,
		&record.domainID, &record.subscriptionID, &record.initialDeviceID,
		&record.createdAtMilliseconds,
	)
	if err == pgx.ErrNoRows {
		return deviceSyncSpaceRecord{}, false, nil
	}
	if err != nil {
		return deviceSyncSpaceRecord{}, false, fmt.Errorf("load Device Sync Space: %w", err)
	}
	return record, true, nil
}

func deviceSyncSpaceProvisioningEqual(
	record deviceSyncSpaceRecord,
	provisioning devicesync.SpaceProvisioning,
) bool {
	return record.version == provisioning.Version &&
		record.retryID == provisioning.RetryID &&
		record.principalID == provisioning.PrincipalID &&
		record.spaceID == provisioning.SpaceID &&
		record.domainID == provisioning.Domain.Registration.DomainID &&
		record.subscriptionID == provisioning.Domain.Subscription.SubscriptionID &&
		record.initialDeviceID == provisioning.InitialDeviceID &&
		record.createdAtMilliseconds == provisioning.CreatedAtMilliseconds
}

func deviceSyncSpaceResult(
	provisioning devicesync.SpaceProvisioning,
	relayResult relay.DomainProvisioningResult,
	acceptance relay.Acceptance,
) devicesync.SpaceProvisioningResult {
	relayResult.Acceptance = acceptance
	return devicesync.SpaceProvisioningResult{
		Acceptance: acceptance, PrincipalID: provisioning.PrincipalID,
		SpaceID: provisioning.SpaceID, Domain: relayResult,
	}
}

func (s *RelayStore) CreateSpaceDeviceAdmission(
	ctx context.Context,
	credential relay.AdministrationCredential,
	admission devicesync.SpaceDeviceAdmission,
	nowMilliseconds int64,
) (devicesync.SpaceDeviceAdmissionCreateResult, error) {
	if err := admission.Validate(); err != nil {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, err
	}
	if admission.CreatedAtMilliseconds > nowMilliseconds ||
		admission.RelayAdmission.ExpiresAtMilliseconds <= nowMilliseconds {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeInvalidAdmission, "Space device admission is not currently issuable",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, fmt.Errorf("begin Device Sync Space device admission: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	space, err := loadDeviceSyncSpaceAuthority(
		ctx, tx, admission.PrincipalID, admission.SpaceID, "FOR UPDATE",
	)
	if err != nil {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, err
	}
	if credential.TenantID != admission.PrincipalID ||
		credential.DomainID != space.domainID ||
		admission.RelayAdmission.TenantID != admission.PrincipalID ||
		admission.RelayAdmission.DomainID != space.domainID ||
		admission.SubscriptionID != space.subscriptionID {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeWrongScope, "Space device admission belongs to another Space domain",
		)
	}
	var enrolled bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM device_sync_devices
			WHERE principal_id=$1 AND device_id=$2
		)
	`, admission.PrincipalID, admission.DeviceID).Scan(&enrolled); err != nil {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, fmt.Errorf("check enrolled Device Sync Space device: %w", err)
	}
	if !enrolled {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeUnauthorized, "Space device is not enrolled in the Device Sync principal",
		)
	}

	existing, found, err := loadDeviceSyncSpaceDeviceAdmissionForCreation(ctx, tx, admission)
	if err != nil {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, err
	}
	if found {
		if !deviceSyncSpaceDeviceAdmissionCreationEqual(existing, admission) {
			if existing.deviceID == admission.DeviceID {
				return devicesync.SpaceDeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
					devicesync.CodeDeviceCollision, "device already has another pending Space admission",
				)
			}
			return devicesync.SpaceDeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
				devicesync.CodeAdmissionCollision, "Space device admission ID or retry ID was reused",
			)
		}
		relayResult, err := s.createSubscriptionAdmissionTx(
			ctx, tx, credential, admission.SubscriptionID,
			admission.RelayAdmission, nowMilliseconds,
		)
		if err != nil {
			return devicesync.SpaceDeviceAdmissionCreateResult{}, err
		}
		return devicesync.SpaceDeviceAdmissionCreateResult{
			Acceptance: relayResult.Acceptance, Admission: admission,
		}, nil
	}
	var admitted bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM device_sync_space_devices
			WHERE principal_id=$1 AND space_id=$2 AND device_id=$3
		)
	`, admission.PrincipalID, admission.SpaceID, admission.DeviceID).Scan(&admitted); err != nil {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, fmt.Errorf("check admitted Device Sync Space device: %w", err)
	}
	if admitted {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeDeviceCollision, "device is already admitted to the Space",
		)
	}

	relayResult, err := s.createSubscriptionAdmissionTx(
		ctx, tx, credential, admission.SubscriptionID,
		admission.RelayAdmission, nowMilliseconds,
	)
	if err != nil {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, err
	}
	if relayResult.Acceptance != relay.AcceptanceAccepted {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, devicesync.NewProtocolError(
			devicesync.CodeAdmissionCollision, "Space device relay admission already exists",
		)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_sync_space_device_admissions (
			principal_id,space_id,retry_id,device_id,domain_id,
			subscription_id,admission_id,version,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, admission.PrincipalID, admission.SpaceID, admission.RetryID,
		admission.DeviceID, admission.RelayAdmission.DomainID,
		admission.SubscriptionID, admission.RelayAdmission.AdmissionID,
		admission.Version, admission.CreatedAtMilliseconds); err != nil {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, fmt.Errorf("insert Device Sync Space device admission: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return devicesync.SpaceDeviceAdmissionCreateResult{}, fmt.Errorf("commit Device Sync Space device admission: %w", err)
	}
	return devicesync.SpaceDeviceAdmissionCreateResult{
		Acceptance: relay.AcceptanceAccepted, Admission: admission,
	}, nil
}

func (s *RelayStore) ClaimSpaceDeviceAdmission(
	ctx context.Context,
	credential devicesync.SpaceDeviceAdmissionCredential,
	claim devicesync.SpaceDeviceAdmissionClaim,
	nowMilliseconds int64,
) (devicesync.SpaceDeviceAdmissionClaimResult, error) {
	if err := claim.Validate(); err != nil {
		return devicesync.SpaceDeviceAdmissionClaimResult{}, err
	}
	if claim.ClaimedAtMilliseconds != nowMilliseconds {
		return devicesync.SpaceDeviceAdmissionClaimResult{}, devicesync.NewProtocolError(
			devicesync.CodeInvalidAdmission, "Space device claim time differs from server time",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return devicesync.SpaceDeviceAdmissionClaimResult{}, fmt.Errorf("begin Device Sync Space device claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	record, err := loadDeviceSyncSpaceDeviceAdmissionForClaim(
		ctx, tx, credential.PrincipalID, credential.SpaceID, credential.AdmissionID,
	)
	if err != nil {
		return devicesync.SpaceDeviceAdmissionClaimResult{}, err
	}
	if claim.PrincipalID != record.principalID || claim.SpaceID != record.spaceID ||
		claim.DeviceID != record.deviceID {
		return devicesync.SpaceDeviceAdmissionClaimResult{}, devicesync.NewProtocolError(
			devicesync.CodeWrongScope, "Space device claim belongs to another admission",
		)
	}
	relayResult, err := s.claimSubscriptionAdmissionTx(
		ctx, tx,
		relay.AdmissionCredential{
			TenantID: record.principalID, DomainID: record.domainID,
			AdmissionID: credential.AdmissionID, Token: credential.Token,
		},
		claim.RelayClaim,
		nowMilliseconds,
	)
	if err != nil {
		return devicesync.SpaceDeviceAdmissionClaimResult{}, err
	}
	if record.claimedAtMilliseconds != nil {
		if record.claimedMemberID == nil || *record.claimedMemberID != claim.DeviceID ||
			relayResult.Acceptance != relay.AcceptanceDuplicate {
			return devicesync.SpaceDeviceAdmissionClaimResult{}, devicesync.NewProtocolError(
				devicesync.CodeAdmissionClaimed, "Space device admission was already claimed",
			)
		}
		return deviceSyncSpaceDeviceClaimResult(claim, relayResult, relay.AcceptanceDuplicate), nil
	}
	if relayResult.Acceptance != relay.AcceptanceAccepted {
		return devicesync.SpaceDeviceAdmissionClaimResult{}, devicesync.NewProtocolError(
			devicesync.CodeAdmissionClaimed, "Space device relay admission was already claimed",
		)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_sync_space_devices (
			principal_id,space_id,device_id,domain_id,subscription_id,
			member_id,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, claim.PrincipalID, claim.SpaceID, claim.DeviceID, record.domainID,
		record.subscriptionID, relayResult.Member.MemberRegistration.MemberID,
		nowMilliseconds); err != nil {
		return devicesync.SpaceDeviceAdmissionClaimResult{}, fmt.Errorf("insert admitted Device Sync Space device: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE device_sync_space_device_admissions
		SET claimed_at_milliseconds=$4,claimed_member_id=$5,updated_at=now()
		WHERE principal_id=$1 AND space_id=$2 AND admission_id=$3
	`, claim.PrincipalID, claim.SpaceID, credential.AdmissionID,
		nowMilliseconds, relayResult.Member.MemberRegistration.MemberID); err != nil {
		return devicesync.SpaceDeviceAdmissionClaimResult{}, fmt.Errorf("claim Device Sync Space device admission: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return devicesync.SpaceDeviceAdmissionClaimResult{}, fmt.Errorf("commit Device Sync Space device claim: %w", err)
	}
	return deviceSyncSpaceDeviceClaimResult(claim, relayResult, relay.AcceptanceAccepted), nil
}

type deviceSyncSpaceAuthority struct {
	principalID    uuid.UUID
	spaceID        uuid.UUID
	domainID       uuid.UUID
	subscriptionID uuid.UUID
}

func loadDeviceSyncSpaceAuthority(
	ctx context.Context,
	querier relayQuerier,
	principalID uuid.UUID,
	spaceID uuid.UUID,
	lock string,
) (deviceSyncSpaceAuthority, error) {
	var authority deviceSyncSpaceAuthority
	query := `
		SELECT principal_id,space_id,domain_id,subscription_id
		FROM device_sync_spaces
		WHERE principal_id=$1 AND space_id=$2`
	if lock != "" {
		query += " " + lock
	}
	err := querier.QueryRow(ctx, query, principalID, spaceID).Scan(
		&authority.principalID, &authority.spaceID,
		&authority.domainID, &authority.subscriptionID,
	)
	if err == pgx.ErrNoRows {
		return deviceSyncSpaceAuthority{}, devicesync.NewProtocolError(
			devicesync.CodeUnauthorized, "Device Sync Space was not found",
		)
	}
	if err != nil {
		return deviceSyncSpaceAuthority{}, fmt.Errorf("load Device Sync Space authority: %w", err)
	}
	return authority, nil
}

type deviceSyncSpaceDeviceAdmissionRecord struct {
	version               int
	retryID               uuid.UUID
	principalID           uuid.UUID
	spaceID               uuid.UUID
	deviceID              uuid.UUID
	domainID              uuid.UUID
	subscriptionID        uuid.UUID
	admissionID           uuid.UUID
	createdAtMilliseconds int64
	claimedAtMilliseconds *int64
	claimedMemberID       *uuid.UUID
}

func loadDeviceSyncSpaceDeviceAdmissionForCreation(
	ctx context.Context,
	tx pgx.Tx,
	admission devicesync.SpaceDeviceAdmission,
) (deviceSyncSpaceDeviceAdmissionRecord, bool, error) {
	var record deviceSyncSpaceDeviceAdmissionRecord
	err := tx.QueryRow(ctx, `
		SELECT version,retry_id,principal_id,space_id,device_id,domain_id,
			subscription_id,admission_id,created_at_milliseconds,
			claimed_at_milliseconds,claimed_member_id
		FROM device_sync_space_device_admissions
		WHERE principal_id=$1 AND space_id=$2 AND (
			admission_id=$3 OR retry_id=$4 OR
			(device_id=$5 AND claimed_at_milliseconds IS NULL)
		)
		FOR UPDATE
	`, admission.PrincipalID, admission.SpaceID,
		admission.RelayAdmission.AdmissionID, admission.RetryID,
		admission.DeviceID).Scan(
		&record.version, &record.retryID, &record.principalID, &record.spaceID,
		&record.deviceID, &record.domainID, &record.subscriptionID,
		&record.admissionID, &record.createdAtMilliseconds,
		&record.claimedAtMilliseconds, &record.claimedMemberID,
	)
	if err == pgx.ErrNoRows {
		return deviceSyncSpaceDeviceAdmissionRecord{}, false, nil
	}
	if err != nil {
		return deviceSyncSpaceDeviceAdmissionRecord{}, false, fmt.Errorf("load Device Sync Space device admission: %w", err)
	}
	return record, true, nil
}

func loadDeviceSyncSpaceDeviceAdmissionForClaim(
	ctx context.Context,
	tx pgx.Tx,
	principalID uuid.UUID,
	spaceID uuid.UUID,
	admissionID uuid.UUID,
) (deviceSyncSpaceDeviceAdmissionRecord, error) {
	var record deviceSyncSpaceDeviceAdmissionRecord
	err := tx.QueryRow(ctx, `
		SELECT version,retry_id,principal_id,space_id,device_id,domain_id,
			subscription_id,admission_id,created_at_milliseconds,
			claimed_at_milliseconds,claimed_member_id
		FROM device_sync_space_device_admissions
		WHERE principal_id=$1 AND space_id=$2 AND admission_id=$3
		FOR UPDATE
	`, principalID, spaceID, admissionID).Scan(
		&record.version, &record.retryID, &record.principalID, &record.spaceID,
		&record.deviceID, &record.domainID, &record.subscriptionID,
		&record.admissionID, &record.createdAtMilliseconds,
		&record.claimedAtMilliseconds, &record.claimedMemberID,
	)
	if err == pgx.ErrNoRows {
		return deviceSyncSpaceDeviceAdmissionRecord{}, devicesync.NewProtocolError(
			devicesync.CodeAdmissionNotFound, "Space device admission was not found",
		)
	}
	if err != nil {
		return deviceSyncSpaceDeviceAdmissionRecord{}, fmt.Errorf("load Device Sync Space device admission: %w", err)
	}
	return record, nil
}

func deviceSyncSpaceDeviceAdmissionCreationEqual(
	record deviceSyncSpaceDeviceAdmissionRecord,
	admission devicesync.SpaceDeviceAdmission,
) bool {
	return record.version == admission.Version && record.retryID == admission.RetryID &&
		record.principalID == admission.PrincipalID && record.spaceID == admission.SpaceID &&
		record.deviceID == admission.DeviceID && record.domainID == admission.RelayAdmission.DomainID &&
		record.subscriptionID == admission.SubscriptionID &&
		record.admissionID == admission.RelayAdmission.AdmissionID &&
		record.createdAtMilliseconds == admission.CreatedAtMilliseconds
}

func deviceSyncSpaceDeviceClaimResult(
	claim devicesync.SpaceDeviceAdmissionClaim,
	relayResult relay.SubscriptionAdmissionClaimResult,
	acceptance relay.Acceptance,
) devicesync.SpaceDeviceAdmissionClaimResult {
	return devicesync.SpaceDeviceAdmissionClaimResult{
		Acceptance: acceptance, PrincipalID: claim.PrincipalID,
		SpaceID: claim.SpaceID, DeviceID: claim.DeviceID, Member: relayResult.Member,
	}
}

type deviceSyncDeviceAdmissionRecord struct {
	version               int
	retryID               uuid.UUID
	principalID           uuid.UUID
	deviceID              uuid.UUID
	controlDomainID       uuid.UUID
	subscriptionID        uuid.UUID
	admissionID           uuid.UUID
	createdAtMilliseconds int64
	claimedAtMilliseconds *int64
	claimedMemberID       *uuid.UUID
}

func loadDeviceSyncDeviceAdmissionForCreation(
	ctx context.Context,
	tx pgx.Tx,
	admission devicesync.DeviceAdmission,
) (deviceSyncDeviceAdmissionRecord, bool, error) {
	var record deviceSyncDeviceAdmissionRecord
	err := tx.QueryRow(ctx, `
		SELECT version,retry_id,principal_id,device_id,control_domain_id,
			subscription_id,admission_id,created_at_milliseconds,
			claimed_at_milliseconds,claimed_member_id
		FROM device_sync_device_admissions
		WHERE principal_id=$1 AND (
			admission_id=$2 OR retry_id=$3 OR
			(device_id=$4 AND claimed_at_milliseconds IS NULL)
		)
		FOR UPDATE
	`, admission.PrincipalID, admission.RelayAdmission.AdmissionID,
		admission.RetryID, admission.DeviceID).Scan(
		&record.version, &record.retryID, &record.principalID, &record.deviceID,
		&record.controlDomainID, &record.subscriptionID, &record.admissionID,
		&record.createdAtMilliseconds, &record.claimedAtMilliseconds,
		&record.claimedMemberID,
	)
	if err == pgx.ErrNoRows {
		return deviceSyncDeviceAdmissionRecord{}, false, nil
	}
	if err != nil {
		return deviceSyncDeviceAdmissionRecord{}, false, fmt.Errorf("load Device Sync device admission: %w", err)
	}
	return record, true, nil
}

func loadDeviceSyncDeviceAdmissionForClaim(
	ctx context.Context,
	tx pgx.Tx,
	principalID uuid.UUID,
	admissionID uuid.UUID,
) (deviceSyncDeviceAdmissionRecord, error) {
	var record deviceSyncDeviceAdmissionRecord
	err := tx.QueryRow(ctx, `
		SELECT version,retry_id,principal_id,device_id,control_domain_id,
			subscription_id,admission_id,created_at_milliseconds,
			claimed_at_milliseconds,claimed_member_id
		FROM device_sync_device_admissions
		WHERE principal_id=$1 AND admission_id=$2
		FOR UPDATE
	`, principalID, admissionID).Scan(
		&record.version, &record.retryID, &record.principalID, &record.deviceID,
		&record.controlDomainID, &record.subscriptionID, &record.admissionID,
		&record.createdAtMilliseconds, &record.claimedAtMilliseconds,
		&record.claimedMemberID,
	)
	if err == pgx.ErrNoRows {
		return deviceSyncDeviceAdmissionRecord{}, devicesync.NewProtocolError(
			devicesync.CodeAdmissionNotFound, "device admission was not found",
		)
	}
	if err != nil {
		return deviceSyncDeviceAdmissionRecord{}, fmt.Errorf("load Device Sync device admission: %w", err)
	}
	return record, nil
}

func deviceSyncDeviceAdmissionCreationEqual(
	record deviceSyncDeviceAdmissionRecord,
	admission devicesync.DeviceAdmission,
) bool {
	return record.version == admission.Version &&
		record.retryID == admission.RetryID &&
		record.principalID == admission.PrincipalID &&
		record.deviceID == admission.DeviceID &&
		record.controlDomainID == admission.RelayAdmission.DomainID &&
		record.subscriptionID == admission.SubscriptionID &&
		record.admissionID == admission.RelayAdmission.AdmissionID &&
		record.createdAtMilliseconds == admission.CreatedAtMilliseconds
}

func deviceSyncDeviceClaimResult(
	claim devicesync.DeviceAdmissionClaim,
	relayResult relay.SubscriptionAdmissionClaimResult,
	acceptance relay.Acceptance,
) devicesync.DeviceAdmissionClaimResult {
	return devicesync.DeviceAdmissionClaimResult{
		Acceptance: acceptance, PrincipalID: claim.PrincipalID,
		DeviceID: claim.DeviceID, Member: relayResult.Member,
	}
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
