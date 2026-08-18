package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/relay"
)

func (s *RelayStore) ProvisionTenant(
	ctx context.Context,
	tenant relay.TenantRegistration,
	initial relay.DomainProvisioning,
) (relay.TenantProvisioningResult, error) {
	if err := tenant.Validate(); err != nil {
		return relay.TenantProvisioningResult{}, err
	}
	if err := initial.Validate(); err != nil {
		return relay.TenantProvisioningResult{}, err
	}
	if tenant.TenantID != initial.Registration.TenantID ||
		tenant.CreatedAtMilliseconds != initial.Registration.CreatedAtMilliseconds {
		return relay.TenantProvisioningResult{}, relay.NewProtocolError(relay.CodeWrongScope, "initial domain belongs to another tenant")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.TenantProvisioningResult{}, fmt.Errorf("begin tenant provisioning: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := s.provisionTenantTx(ctx, tx, tenant, initial)
	if err != nil {
		return relay.TenantProvisioningResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.TenantProvisioningResult{}, fmt.Errorf("commit tenant provisioning: %w", err)
	}
	return result, nil
}

func (s *RelayStore) provisionTenantTx(
	ctx context.Context,
	tx pgx.Tx,
	tenant relay.TenantRegistration,
	initial relay.DomainProvisioning,
) (relay.TenantProvisioningResult, error) {
	result, err := tx.Exec(ctx, `
		INSERT INTO relay_tenants (
			tenant_id, version, provisioning_retry_id,
			provisioning_authorization_digest, created_at_milliseconds,
			maximum_domain_count, maximum_aggregate_message_count,
			maximum_aggregate_message_byte_count, maximum_aggregate_blob_count,
			maximum_aggregate_blob_byte_count
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT DO NOTHING
	`, tenant.TenantID, tenant.Version, tenant.RetryID, tenant.AuthorizationDigest,
		tenant.CreatedAtMilliseconds, tenant.MaximumDomainCount,
		tenant.MaximumAggregateMessageCount, tenant.MaximumAggregateMessageByteCount,
		tenant.MaximumAggregateBlobCount, tenant.MaximumAggregateBlobByteCount)
	if err != nil {
		return relay.TenantProvisioningResult{}, fmt.Errorf("insert relay tenant: %w", err)
	}
	if result.RowsAffected() == 0 {
		var conflictingTenantID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM relay_tenants WHERE tenant_id=$1 OR provisioning_retry_id=$2`, tenant.TenantID, tenant.RetryID).Scan(&conflictingTenantID); err != nil {
			return relay.TenantProvisioningResult{}, err
		}
		if conflictingTenantID != tenant.TenantID {
			return relay.TenantProvisioningResult{}, relay.NewProtocolError(relay.CodeTenantCollision, "tenant retry ID was reused")
		}
		existing, err := loadRelayTenant(ctx, tx, tenant.TenantID, "FOR UPDATE")
		if err != nil {
			return relay.TenantProvisioningResult{}, err
		}
		if existing != tenant {
			return relay.TenantProvisioningResult{}, relay.NewProtocolError(relay.CodeTenantCollision, "tenant ID or retry ID was reused")
		}
		equal, err := postgresDomainProvisioningEqual(ctx, tx, initial)
		if err != nil {
			return relay.TenantProvisioningResult{}, err
		}
		if !equal {
			return relay.TenantProvisioningResult{}, relay.NewProtocolError(relay.CodeTenantCollision, "initial domain differs from exact retry")
		}
		return postgresTenantProvisioningResult(tenant, initial, relay.AcceptanceDuplicate), nil
	}
	if err := insertSubscriptionDomain(ctx, tx, initial); err != nil {
		return relay.TenantProvisioningResult{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_tenants SET domain_count = 1, updated_at = now() WHERE tenant_id = $1`, tenant.TenantID); err != nil {
		return relay.TenantProvisioningResult{}, fmt.Errorf("advance tenant domain count: %w", err)
	}
	if err := insertDataPlaneAudit(ctx, tx, tenant.TenantID, nil, nil, nil, "tenant_created", tenant.CreatedAtMilliseconds); err != nil {
		return relay.TenantProvisioningResult{}, err
	}
	if err := auditProvisionedDomain(ctx, tx, initial); err != nil {
		return relay.TenantProvisioningResult{}, err
	}
	return postgresTenantProvisioningResult(tenant, initial, relay.AcceptanceAccepted), nil
}

func (s *RelayStore) ProvisionDomain(
	ctx context.Context,
	credential relay.TenantCredential,
	domain relay.DomainProvisioning,
	nowMilliseconds int64,
) (relay.DomainProvisioningResult, error) {
	if err := domain.Validate(); err != nil {
		return relay.DomainProvisioningResult{}, err
	}
	if credential.TenantID != domain.Registration.TenantID ||
		domain.Registration.CreatedAtMilliseconds > nowMilliseconds {
		return relay.DomainProvisioningResult{}, relay.NewProtocolError(relay.CodeWrongScope, "domain belongs to another tenant")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.DomainProvisioningResult{}, fmt.Errorf("begin domain provisioning: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := s.provisionDomainTx(ctx, tx, credential, domain, nowMilliseconds)
	if err != nil {
		return relay.DomainProvisioningResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.DomainProvisioningResult{}, fmt.Errorf("commit domain provisioning: %w", err)
	}
	return result, nil
}

func (s *RelayStore) provisionDomainTx(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.TenantCredential,
	domain relay.DomainProvisioning,
	nowMilliseconds int64,
) (relay.DomainProvisioningResult, error) {
	tenant, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE")
	if err != nil {
		return relay.DomainProvisioningResult{}, err
	}
	if err := tenant.Authorize(credential); err != nil {
		return relay.DomainProvisioningResult{}, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM relay_domains WHERE tenant_id=$1 AND domain_id=$2)`, credential.TenantID, domain.Registration.DomainID).Scan(&exists); err != nil {
		return relay.DomainProvisioningResult{}, err
	}
	if exists {
		equal, err := postgresDomainProvisioningEqual(ctx, tx, domain)
		if err != nil {
			return relay.DomainProvisioningResult{}, err
		}
		if !equal {
			return relay.DomainProvisioningResult{}, relay.NewProtocolError(relay.CodeDomainCollision, "domain ID was reused")
		}
		return postgresDomainProvisioningResult(domain, relay.AcceptanceDuplicate), nil
	}
	var retryDomainID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT domain_id FROM relay_domains WHERE tenant_id=$1 AND provisioning_retry_id=$2`, credential.TenantID, domain.RetryID).Scan(&retryDomainID)
	if err == nil {
		return relay.DomainProvisioningResult{}, relay.NewProtocolError(relay.CodeDomainCollision, "domain retry ID was reused")
	}
	if err != pgx.ErrNoRows {
		return relay.DomainProvisioningResult{}, err
	}
	var domainCount int
	if err := tx.QueryRow(ctx, `SELECT domain_count FROM relay_tenants WHERE tenant_id=$1`, credential.TenantID).Scan(&domainCount); err != nil {
		return relay.DomainProvisioningResult{}, err
	}
	if domainCount >= tenant.MaximumDomainCount {
		return relay.DomainProvisioningResult{}, relay.NewProtocolError(relay.CodeTenantFull, "tenant reached its domain limit")
	}
	if err := insertSubscriptionDomain(ctx, tx, domain); err != nil {
		return relay.DomainProvisioningResult{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_tenants SET domain_count=domain_count+1, updated_at=now() WHERE tenant_id=$1`, credential.TenantID); err != nil {
		return relay.DomainProvisioningResult{}, fmt.Errorf("advance tenant domain count: %w", err)
	}
	if err := auditProvisionedDomain(ctx, tx, domain); err != nil {
		return relay.DomainProvisioningResult{}, err
	}
	return postgresDomainProvisioningResult(domain, relay.AcceptanceAccepted), nil
}

func (s *RelayStore) RotateTenantCredential(
	ctx context.Context,
	credential relay.TenantCredential,
	rotation relay.TenantCredentialRotation,
) (relay.TenantCredentialRotationResult, error) {
	if err := rotation.Validate(); err != nil {
		return relay.TenantCredentialRotationResult{}, err
	}
	actualDigest, err := relay.TenantAuthorizationDigest(credential)
	if err != nil {
		return relay.TenantCredentialRotationResult{}, relay.NewProtocolError(relay.CodeUnauthorized, "tenant credential is invalid")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.TenantCredentialRotationResult{}, fmt.Errorf("begin tenant credential rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenant, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE")
	if err != nil {
		return relay.TenantCredentialRotationResult{}, err
	}
	var previous, next string
	var rotatedAt int64
	err = tx.QueryRow(ctx, `SELECT previous_authorization_digest,new_authorization_digest,rotated_at_milliseconds FROM relay_tenant_credential_rotations WHERE tenant_id=$1 AND rotation_id=$2`, credential.TenantID, rotation.RotationID).Scan(&previous, &next, &rotatedAt)
	if err == nil {
		if (actualDigest == previous || actualDigest == next) && next == rotation.ReplacementAuthorizationDigest && rotatedAt == rotation.RotatedAtMilliseconds && rotation.TenantID == credential.TenantID {
			return relay.TenantCredentialRotationResult{Acceptance: relay.AcceptanceDuplicate, RotationID: rotation.RotationID, TenantID: credential.TenantID, AuthorizationDigest: next, RotatedAtMilliseconds: rotatedAt}, nil
		}
		return relay.TenantCredentialRotationResult{}, relay.NewProtocolError(relay.CodeCredentialRotationCollision, "tenant rotation ID was reused")
	}
	if err != pgx.ErrNoRows {
		return relay.TenantCredentialRotationResult{}, err
	}
	if err := tenant.Authorize(credential); err != nil {
		return relay.TenantCredentialRotationResult{}, err
	}
	if rotation.TenantID != credential.TenantID || rotation.RotatedAtMilliseconds < tenant.CreatedAtMilliseconds {
		return relay.TenantCredentialRotationResult{}, relay.NewProtocolError(relay.CodeWrongScope, "tenant rotation has invalid scope or time")
	}
	var used bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM relay_tenant_credential_rotations WHERE tenant_id=$1 AND ($2=previous_authorization_digest OR $2=new_authorization_digest))`, credential.TenantID, rotation.ReplacementAuthorizationDigest).Scan(&used); err != nil {
		return relay.TenantCredentialRotationResult{}, err
	}
	if used || rotation.ReplacementAuthorizationDigest == tenant.AuthorizationDigest {
		return relay.TenantCredentialRotationResult{}, relay.NewProtocolError(relay.CodeCredentialReuse, "tenant credential digest was already used")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_tenant_credential_rotations VALUES ($1,$2,$3,$4,$5,now())`, credential.TenantID, rotation.RotationID, tenant.AuthorizationDigest, rotation.ReplacementAuthorizationDigest, rotation.RotatedAtMilliseconds); err != nil {
		return relay.TenantCredentialRotationResult{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_tenants SET provisioning_authorization_digest=$2,updated_at=now() WHERE tenant_id=$1`, credential.TenantID, rotation.ReplacementAuthorizationDigest); err != nil {
		return relay.TenantCredentialRotationResult{}, err
	}
	if err := insertDataPlaneAudit(ctx, tx, credential.TenantID, nil, nil, nil, "tenant_credential_rotated", rotation.RotatedAtMilliseconds); err != nil {
		return relay.TenantCredentialRotationResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.TenantCredentialRotationResult{}, err
	}
	return relay.TenantCredentialRotationResult{Acceptance: relay.AcceptanceAccepted, RotationID: rotation.RotationID, TenantID: credential.TenantID, AuthorizationDigest: rotation.ReplacementAuthorizationDigest, RotatedAtMilliseconds: rotation.RotatedAtMilliseconds}, nil
}

func loadRelayTenant(ctx context.Context, q relayQuerier, tenantID uuid.UUID, lock string) (relay.TenantRegistration, error) {
	var tenant relay.TenantRegistration
	err := q.QueryRow(ctx, `SELECT version,provisioning_retry_id,tenant_id,provisioning_authorization_digest,created_at_milliseconds,maximum_domain_count,maximum_aggregate_message_count,maximum_aggregate_message_byte_count,maximum_aggregate_blob_count,maximum_aggregate_blob_byte_count FROM relay_tenants WHERE tenant_id=$1 `+lock, tenantID).Scan(
		&tenant.Version, &tenant.RetryID, &tenant.TenantID, &tenant.AuthorizationDigest,
		&tenant.CreatedAtMilliseconds, &tenant.MaximumDomainCount,
		&tenant.MaximumAggregateMessageCount, &tenant.MaximumAggregateMessageByteCount,
		&tenant.MaximumAggregateBlobCount, &tenant.MaximumAggregateBlobByteCount,
	)
	if err == pgx.ErrNoRows {
		return relay.TenantRegistration{}, relay.NewProtocolError(relay.CodeTenantNotFound, "tenant was not found")
	}
	if err != nil {
		return relay.TenantRegistration{}, fmt.Errorf("load relay tenant: %w", err)
	}
	return tenant, nil
}

func insertSubscriptionDomain(ctx context.Context, tx pgx.Tx, p relay.DomainProvisioning) error {
	r := p.Registration
	if _, err := tx.Exec(ctx, `INSERT INTO relay_domains (tenant_id,domain_id,provisioning_retry_id,version,administration_digest,created_at_milliseconds,maximum_message_count,maximum_message_byte_count,maximum_blob_count,maximum_blob_byte_count) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.TenantID, r.DomainID, p.RetryID, r.Version, r.AdministrationDigest, r.CreatedAtMilliseconds, r.MaximumMessageCount, r.MaximumMessageByteCount, r.MaximumBlobCount, r.MaximumBlobByteCount); err != nil {
		return fmt.Errorf("insert relay domain: %w", err)
	}
	sub := p.Subscription
	var startSequence *int64
	if sub.StartCursor != nil {
		sequence, err := relay.DecodeCursor(*sub.StartCursor)
		if err != nil {
			return err
		}
		value := int64(sequence)
		startSequence = &value
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_subscriptions (tenant_id,domain_id,subscription_id,create_retry_id,version,status,start_sequence,created_at_milliseconds,updated_at_milliseconds) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, sub.TenantID, sub.DomainID, sub.SubscriptionID, p.RetryID, sub.Version, sub.Status, startSequence, sub.CreatedAtMilliseconds, sub.UpdatedAtMilliseconds); err != nil {
		return fmt.Errorf("insert relay subscription: %w", err)
	}
	return insertRelayMemberWithSubscription(ctx, tx, p.InitialMember, sub.SubscriptionID)
}

func postgresDomainProvisioningEqual(ctx context.Context, q relayQuerier, p relay.DomainProvisioning) (bool, error) {
	var retryID, subscriptionID, memberID uuid.UUID
	var adminDigest, memberDigest string
	err := q.QueryRow(ctx, `SELECT d.provisioning_retry_id,s.subscription_id,m.member_id,d.administration_digest,m.authorization_digest FROM relay_domains d JOIN relay_subscriptions s USING (tenant_id,domain_id) JOIN relay_members m ON m.tenant_id=d.tenant_id AND m.domain_id=d.domain_id AND m.subscription_id=s.subscription_id WHERE d.tenant_id=$1 AND d.domain_id=$2 AND s.subscription_id=$3 AND m.member_id=$4`, p.Registration.TenantID, p.Registration.DomainID, p.Subscription.SubscriptionID, p.InitialMember.MemberID).Scan(&retryID, &subscriptionID, &memberID, &adminDigest, &memberDigest)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return retryID == p.RetryID && subscriptionID == p.Subscription.SubscriptionID && memberID == p.InitialMember.MemberID && adminDigest == p.Registration.AdministrationDigest && memberDigest == p.InitialMember.AuthorizationDigest, nil
}

func insertRelayMemberWithSubscription(ctx context.Context, tx pgx.Tx, m relay.MemberRegistration, subscriptionID uuid.UUID) error {
	_, err := tx.Exec(ctx, `INSERT INTO relay_members (tenant_id,domain_id,member_id,subscription_id,version,authorization_digest,capabilities,created_at_milliseconds,expires_at_milliseconds,revoked_at_milliseconds) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, m.TenantID, m.DomainID, m.MemberID, subscriptionID, m.Version, m.AuthorizationDigest, capabilityStrings(m.Capabilities), m.CreatedAtMilliseconds, m.ExpiresAtMilliseconds, m.RevokedAtMilliseconds)
	if err != nil {
		return fmt.Errorf("insert relay member: %w", err)
	}
	return nil
}

func postgresDomainProvisioningResult(p relay.DomainProvisioning, acceptance relay.Acceptance) relay.DomainProvisioningResult {
	return relay.DomainProvisioningResult{Acceptance: acceptance, RetryID: p.RetryID, TenantID: p.Registration.TenantID, DomainID: p.Registration.DomainID, SubscriptionID: p.Subscription.SubscriptionID, MemberID: p.InitialMember.MemberID, AdministrationAuthorizationDigest: p.Registration.AdministrationDigest, MemberAuthorizationDigest: p.InitialMember.AuthorizationDigest}
}

func postgresTenantProvisioningResult(t relay.TenantRegistration, p relay.DomainProvisioning, acceptance relay.Acceptance) relay.TenantProvisioningResult {
	return relay.TenantProvisioningResult{Acceptance: acceptance, RetryID: t.RetryID, TenantProvisioningAuthorizationDigest: t.AuthorizationDigest, InitialDomain: postgresDomainProvisioningResult(p, acceptance)}
}

func insertDataPlaneAudit(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, domainID, subscriptionID, memberID *uuid.UUID, eventType string, occurred int64) error {
	_, err := tx.Exec(ctx, `INSERT INTO relay_audit_events (tenant_id,domain_id,subscription_id,member_id,event_type,occurred_at_milliseconds) VALUES ($1,$2,$3,$4,$5,$6)`, tenantID, domainID, subscriptionID, memberID, eventType, occurred)
	return err
}

func auditProvisionedDomain(ctx context.Context, tx pgx.Tx, provisioning relay.DomainProvisioning) error {
	tenantID := provisioning.Registration.TenantID
	domainID := provisioning.Registration.DomainID
	subscriptionID := provisioning.Subscription.SubscriptionID
	memberID := provisioning.InitialMember.MemberID
	for _, event := range []struct {
		typeName string
		memberID *uuid.UUID
	}{
		{typeName: "domain_created"},
		{typeName: "subscription_created"},
		{typeName: "member_created", memberID: &memberID},
	} {
		if err := insertDataPlaneAudit(ctx, tx, tenantID, &domainID, &subscriptionID, event.memberID, event.typeName, provisioning.Registration.CreatedAtMilliseconds); err != nil {
			return err
		}
	}
	return nil
}

func (s *RelayStore) CreateSubscriptionMember(
	ctx context.Context,
	credential relay.AdministrationCredential,
	subscriptionID uuid.UUID,
	registration relay.MemberRegistration,
	nowMilliseconds int64,
) (relay.Acceptance, error) {
	if err := registration.Validate(); err != nil {
		return "", err
	}
	if subscriptionID == uuid.Nil || registration.CreatedAtMilliseconds > nowMilliseconds {
		return "", relay.NewProtocolError(relay.CodeInvalidSubscription, "member subscription is invalid")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return "", err
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE")
	if err != nil {
		return "", err
	}
	if err := domain.Authorize(credential); err != nil {
		return "", err
	}
	if registration.TenantID != credential.TenantID || registration.DomainID != credential.DomainID {
		return "", relay.NewProtocolError(relay.CodeWrongScope, "member belongs to another domain")
	}
	status, err := loadSubscriptionStatus(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "FOR SHARE")
	if err != nil {
		return "", err
	}
	if status != relay.SubscriptionActive {
		return "", relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription is not active")
	}
	var existingDigest string
	var existingSubscription uuid.UUID
	err = tx.QueryRow(ctx, `SELECT authorization_digest,subscription_id FROM relay_members WHERE tenant_id=$1 AND domain_id=$2 AND member_id=$3`, registration.TenantID, registration.DomainID, registration.MemberID).Scan(&existingDigest, &existingSubscription)
	if err == nil {
		if existingDigest == registration.AuthorizationDigest && existingSubscription == subscriptionID {
			return relay.AcceptanceDuplicate, nil
		}
		return "", relay.NewProtocolError(relay.CodeMemberCollision, "member ID was reused")
	}
	if err != pgx.ErrNoRows {
		return "", err
	}
	if err := ensurePostgresMemberCapacity(ctx, tx, registration.TenantID, registration.DomainID, nowMilliseconds); err != nil {
		return "", err
	}
	if err := insertRelayMemberWithSubscription(ctx, tx, registration, subscriptionID); err != nil {
		return "", err
	}
	if err := insertDataPlaneAudit(ctx, tx, registration.TenantID, &registration.DomainID, &subscriptionID, &registration.MemberID, "member_created", nowMilliseconds); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return relay.AcceptanceAccepted, nil
}

func (s *RelayStore) CreateSubscriptionAdmission(
	ctx context.Context,
	credential relay.AdministrationCredential,
	subscriptionID uuid.UUID,
	registration relay.MemberAdmission,
	nowMilliseconds int64,
) (relay.SubscriptionAdmissionCreateResult, error) {
	if err := registration.Validate(); err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	if subscriptionID == uuid.Nil || registration.CreatedAtMilliseconds > nowMilliseconds || registration.ExpiresAtMilliseconds <= nowMilliseconds || registration.RevokedAtMilliseconds != nil || registration.ClaimedAtMilliseconds != nil {
		return relay.SubscriptionAdmissionCreateResult{}, relay.NewProtocolError(relay.CodeInvalidAdmission, "admission is not issuable")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := s.createSubscriptionAdmissionTx(
		ctx, tx, credential, subscriptionID, registration, nowMilliseconds,
	)
	if err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	return result, nil
}

func (s *RelayStore) createSubscriptionAdmissionTx(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.AdministrationCredential,
	subscriptionID uuid.UUID,
	registration relay.MemberAdmission,
	nowMilliseconds int64,
) (relay.SubscriptionAdmissionCreateResult, error) {
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE")
	if err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	if err = domain.Authorize(credential); err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	if registration.TenantID != credential.TenantID || registration.DomainID != credential.DomainID {
		return relay.SubscriptionAdmissionCreateResult{}, relay.NewProtocolError(relay.CodeWrongScope, "admission belongs to another domain")
	}
	status, err := loadSubscriptionStatus(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "FOR SHARE")
	if err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	if status != relay.SubscriptionActive {
		return relay.SubscriptionAdmissionCreateResult{}, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription is not active")
	}
	existing, found, err := loadRelayAdmission(ctx, tx, registration.TenantID, registration.DomainID, registration.AdmissionID, "FOR UPDATE")
	if err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	if found {
		var storedSub uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT subscription_id FROM relay_member_admissions WHERE tenant_id=$1 AND domain_id=$2 AND admission_id=$3`, registration.TenantID, registration.DomainID, registration.AdmissionID).Scan(&storedSub); err != nil {
			return relay.SubscriptionAdmissionCreateResult{}, err
		}
		if admissionCreationEqual(existing, registration) && storedSub == subscriptionID {
			return relay.SubscriptionAdmissionCreateResult{Acceptance: relay.AcceptanceDuplicate, Admission: relay.SubscriptionMemberAdmission{SubscriptionID: subscriptionID, Admission: existing}}, nil
		}
		return relay.SubscriptionAdmissionCreateResult{}, relay.NewProtocolError(relay.CodeAdmissionCollision, "admission ID was reused")
	}
	if err := ensurePostgresAdmissionCapacity(ctx, tx, registration.TenantID, registration.DomainID, nowMilliseconds); err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO relay_member_admissions (tenant_id,domain_id,admission_id,subscription_id,version,authorization_digest,capabilities,created_at_milliseconds,expires_at_milliseconds,member_expires_at_milliseconds) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, registration.TenantID, registration.DomainID, registration.AdmissionID, subscriptionID, registration.Version, registration.AuthorizationDigest, capabilityStrings(registration.Capabilities), registration.CreatedAtMilliseconds, registration.ExpiresAtMilliseconds, registration.MemberExpiresAtMilliseconds)
	if err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	if err := insertDataPlaneAudit(ctx, tx, registration.TenantID, &registration.DomainID, &subscriptionID, nil, "admission_created", nowMilliseconds); err != nil {
		return relay.SubscriptionAdmissionCreateResult{}, err
	}
	return relay.SubscriptionAdmissionCreateResult{Acceptance: relay.AcceptanceAccepted, Admission: relay.SubscriptionMemberAdmission{SubscriptionID: subscriptionID, Admission: registration}}, nil
}

func (s *RelayStore) ClaimSubscriptionAdmission(ctx context.Context, credential relay.AdmissionCredential, claim relay.MemberAdmissionClaim, nowMilliseconds int64) (relay.SubscriptionAdmissionClaimResult, error) {
	if err := claim.Validate(); err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := s.claimSubscriptionAdmissionTx(ctx, tx, credential, claim, nowMilliseconds)
	if err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	return result, nil
}

func (s *RelayStore) claimSubscriptionAdmissionTx(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.AdmissionCredential,
	claim relay.MemberAdmissionClaim,
	nowMilliseconds int64,
) (relay.SubscriptionAdmissionClaimResult, error) {
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	if _, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR SHARE"); err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	admission, found, err := loadRelayAdmission(ctx, tx, credential.TenantID, credential.DomainID, credential.AdmissionID, "FOR UPDATE")
	if err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	if !found {
		return relay.SubscriptionAdmissionClaimResult{}, relay.NewProtocolError(relay.CodeAdmissionNotFound, "admission was not found")
	}
	if err = admission.VerifyCredential(credential); err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	var subscriptionID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT subscription_id FROM relay_member_admissions WHERE tenant_id=$1 AND domain_id=$2 AND admission_id=$3`, credential.TenantID, credential.DomainID, credential.AdmissionID).Scan(&subscriptionID); err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	if admission.ClaimedMemberID != nil {
		member, found, err := loadRelayMember(ctx, tx, credential.TenantID, credential.DomainID, *admission.ClaimedMemberID, "FOR SHARE")
		if err != nil {
			return relay.SubscriptionAdmissionClaimResult{}, err
		}
		if found && member.MemberID == claim.MemberID && member.AuthorizationDigest == claim.AuthorizationDigest {
			return relay.SubscriptionAdmissionClaimResult{Acceptance: relay.AcceptanceDuplicate, Member: relay.SubscriptionMemberRegistration{SubscriptionID: subscriptionID, MemberRegistration: member}}, nil
		}
		return relay.SubscriptionAdmissionClaimResult{}, relay.NewProtocolError(relay.CodeAdmissionClaimed, "admission was already claimed")
	}
	if err = admission.RequireActive(nowMilliseconds); err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	status, err := loadSubscriptionStatus(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "FOR SHARE")
	if err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	if status != relay.SubscriptionActive {
		return relay.SubscriptionAdmissionClaimResult{}, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription is not active")
	}
	member := relay.MemberRegistration{Version: relay.SchemaVersion, TenantID: admission.TenantID, DomainID: admission.DomainID, MemberID: claim.MemberID, AuthorizationDigest: claim.AuthorizationDigest, Capabilities: append([]relay.Capability(nil), admission.Capabilities...), CreatedAtMilliseconds: nowMilliseconds, ExpiresAtMilliseconds: admission.MemberExpiresAtMilliseconds}
	if err = member.Validate(); err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	if err = insertRelayMemberWithSubscription(ctx, tx, member, subscriptionID); err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE relay_member_admissions SET claimed_at_milliseconds=$4,claimed_member_id=$5,updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND admission_id=$3`, admission.TenantID, admission.DomainID, admission.AdmissionID, nowMilliseconds, member.MemberID)
	if err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	if err = insertDataPlaneAudit(ctx, tx, member.TenantID, &member.DomainID, &subscriptionID, &member.MemberID, "admission_claimed", nowMilliseconds); err != nil {
		return relay.SubscriptionAdmissionClaimResult{}, err
	}
	return relay.SubscriptionAdmissionClaimResult{Acceptance: relay.AcceptanceAccepted, Member: relay.SubscriptionMemberRegistration{SubscriptionID: subscriptionID, MemberRegistration: member}}, nil
}

func (s *RelayStore) CreateSubscription(ctx context.Context, credential relay.AdministrationCredential, request relay.SubscriptionCreateRequest) (relay.SubscriptionCreateResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := s.createSubscriptionTx(ctx, tx, credential, request)
	if err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	return result, nil
}

func (s *RelayStore) createSubscriptionTx(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.AdministrationCredential,
	request relay.SubscriptionCreateRequest,
) (relay.SubscriptionCreateResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE")
	if err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	if err := domain.Authorize(credential); err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	existing, existingRetry, found, err := loadSubscription(ctx, tx, credential.TenantID, credential.DomainID, request.SubscriptionID, "FOR UPDATE")
	if err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	if found {
		if existingRetry == request.RetryID && existing.CreatedAtMilliseconds == request.CreatedAtMilliseconds {
			return relay.SubscriptionCreateResponse{Acceptance: relay.AcceptanceDuplicate, RetryID: request.RetryID, Subscription: existing}, nil
		}
		return relay.SubscriptionCreateResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription ID was reused")
	}
	var retrySubscriptionID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT subscription_id FROM relay_subscriptions WHERE tenant_id=$1 AND domain_id=$2 AND create_retry_id=$3`, credential.TenantID, credential.DomainID, request.RetryID).Scan(&retrySubscriptionID)
	if err == nil {
		return relay.SubscriptionCreateResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription retry ID was reused")
	}
	if err != pgx.ErrNoRows {
		return relay.SubscriptionCreateResponse{}, err
	}
	if request.CreatedAtMilliseconds < domain.CreatedAtMilliseconds {
		return relay.SubscriptionCreateResponse{}, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription predates its domain")
	}
	startSequence, err := latestActivatedCheckpointStart(ctx, tx, credential.TenantID, credential.DomainID)
	if err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO relay_subscriptions (tenant_id,domain_id,subscription_id,create_retry_id,version,status,start_sequence,created_at_milliseconds,updated_at_milliseconds) VALUES ($1,$2,$3,$4,1,'active',$5,$6,$6)`, credential.TenantID, credential.DomainID, request.SubscriptionID, request.RetryID, startSequence, request.CreatedAtMilliseconds)
	if err != nil {
		return relay.SubscriptionCreateResponse{}, fmt.Errorf("insert subscription: %w", err)
	}
	if err := insertDataPlaneAudit(ctx, tx, credential.TenantID, &credential.DomainID, &request.SubscriptionID, nil, "subscription_created", request.CreatedAtMilliseconds); err != nil {
		return relay.SubscriptionCreateResponse{}, err
	}
	subscription := relay.Subscription{Version: relay.SchemaVersion, TenantID: credential.TenantID, DomainID: credential.DomainID, SubscriptionID: request.SubscriptionID, Status: relay.SubscriptionActive, StartCursor: cursorFromSequence(startSequence), CreatedAtMilliseconds: request.CreatedAtMilliseconds, UpdatedAtMilliseconds: request.CreatedAtMilliseconds}
	return relay.SubscriptionCreateResponse{Acceptance: relay.AcceptanceAccepted, RetryID: request.RetryID, Subscription: subscription}, nil
}

func (s *RelayStore) GetSubscription(ctx context.Context, credential relay.AdministrationCredential, subscriptionID uuid.UUID) (relay.Subscription, error) {
	if subscriptionID == uuid.Nil {
		return relay.Subscription{}, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription ID is invalid")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.Subscription{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.Subscription{}, err
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR SHARE")
	if err != nil {
		return relay.Subscription{}, err
	}
	if err := domain.Authorize(credential); err != nil {
		return relay.Subscription{}, err
	}
	subscription, _, found, err := loadSubscription(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "FOR SHARE")
	if err != nil {
		return relay.Subscription{}, err
	}
	if !found {
		return relay.Subscription{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "subscription was not found")
	}
	return subscription, nil
}

func (s *RelayStore) RevokeTenantMemberships(
	ctx context.Context,
	credential relay.TenantCredential,
	revocation relay.TenantMembershipRevocation,
) (relay.TenantMembershipRevocationResult, error) {
	if err := revocation.Validate(); err != nil {
		return relay.TenantMembershipRevocationResult{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.TenantMembershipRevocationResult{}, fmt.Errorf("begin tenant membership revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := s.revokeTenantMembershipsTx(ctx, tx, credential, revocation)
	if err != nil {
		return relay.TenantMembershipRevocationResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.TenantMembershipRevocationResult{}, fmt.Errorf("commit tenant membership revocation: %w", err)
	}
	return result, nil
}

func (s *RelayStore) revokeTenantMembershipsTx(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.TenantCredential,
	revocation relay.TenantMembershipRevocation,
) (relay.TenantMembershipRevocationResult, error) {
	tenant, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE")
	if err != nil {
		return relay.TenantMembershipRevocationResult{}, err
	}
	if err := tenant.Authorize(credential); err != nil {
		return relay.TenantMembershipRevocationResult{}, err
	}
	var storedVersion int
	var storedRevokedAt int64
	err = tx.QueryRow(ctx, `
		SELECT version,revoked_at_milliseconds
		FROM relay_tenant_membership_revocations
		WHERE tenant_id=$1 AND retry_id=$2
		FOR UPDATE
	`, credential.TenantID, revocation.RetryID).Scan(&storedVersion, &storedRevokedAt)
	if err == nil {
		storedItems, loadErr := loadTenantMembershipRevocationItems(ctx, tx, credential.TenantID, revocation.RetryID)
		if loadErr != nil {
			return relay.TenantMembershipRevocationResult{}, loadErr
		}
		if storedVersion != revocation.Version || storedRevokedAt != revocation.RevokedAtMilliseconds ||
			!tenantMembershipRevocationItemsEqual(storedItems, revocation.Memberships) {
			return relay.TenantMembershipRevocationResult{}, relay.NewProtocolError(relay.CodeMemberCollision, "tenant membership revocation retry ID was reused")
		}
		return relay.TenantMembershipRevocationResult{
			Acceptance: relay.AcceptanceDuplicate, RetryID: revocation.RetryID,
			RevokedAtMilliseconds: storedRevokedAt, Memberships: storedItems,
		}, nil
	}
	if err != pgx.ErrNoRows {
		return relay.TenantMembershipRevocationResult{}, err
	}
	// Lock and validate the complete target set before changing any row.
	for _, target := range revocation.Memberships {
		member, found, loadErr := loadRelayMember(ctx, tx, credential.TenantID, target.DomainID, target.MemberID, "FOR UPDATE")
		if loadErr != nil {
			return relay.TenantMembershipRevocationResult{}, loadErr
		}
		if !found {
			return relay.TenantMembershipRevocationResult{}, relay.NewProtocolError(relay.CodeMemberNotFound, "revocation member was not found")
		}
		var memberSubscriptionID uuid.UUID
		if loadErr := tx.QueryRow(ctx, `
			SELECT subscription_id FROM relay_members
			WHERE tenant_id=$1 AND domain_id=$2 AND member_id=$3
		`, credential.TenantID, target.DomainID, target.MemberID).Scan(&memberSubscriptionID); loadErr != nil {
			return relay.TenantMembershipRevocationResult{}, loadErr
		}
		if memberSubscriptionID != target.SubscriptionID {
			return relay.TenantMembershipRevocationResult{}, relay.NewProtocolError(relay.CodeMemberNotFound, "revocation member does not own the subscription")
		}
		subscription, _, found, loadErr := loadSubscription(ctx, tx, credential.TenantID, target.DomainID, target.SubscriptionID, "FOR UPDATE")
		if loadErr != nil {
			return relay.TenantMembershipRevocationResult{}, loadErr
		}
		if !found || subscription.Status == relay.SubscriptionRevoked {
			return relay.TenantMembershipRevocationResult{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "active revocation subscription was not found")
		}
		if member.RevokedAtMilliseconds != nil {
			return relay.TenantMembershipRevocationResult{}, relay.NewProtocolError(relay.CodeMemberRevoked, "revocation member was already revoked")
		}
		if revocation.RevokedAtMilliseconds < member.CreatedAtMilliseconds ||
			revocation.RevokedAtMilliseconds < subscription.CreatedAtMilliseconds ||
			revocation.RevokedAtMilliseconds < subscription.UpdatedAtMilliseconds {
			return relay.TenantMembershipRevocationResult{}, relay.NewProtocolError(relay.CodeInvalidMember, "tenant membership revocation is out of order")
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO relay_tenant_membership_revocations
		(tenant_id,retry_id,version,revoked_at_milliseconds)
		VALUES ($1,$2,$3,$4)
	`, credential.TenantID, revocation.RetryID, revocation.Version, revocation.RevokedAtMilliseconds); err != nil {
		return relay.TenantMembershipRevocationResult{}, fmt.Errorf("insert tenant membership revocation: %w", err)
	}
	for ordinal, target := range revocation.Memberships {
		if _, err := tx.Exec(ctx, `
			UPDATE relay_members SET revoked_at_milliseconds=$4,updated_at=now()
			WHERE tenant_id=$1 AND domain_id=$2 AND member_id=$3
		`, credential.TenantID, target.DomainID, target.MemberID, revocation.RevokedAtMilliseconds); err != nil {
			return relay.TenantMembershipRevocationResult{}, fmt.Errorf("revoke tenant relay member: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE relay_subscriptions
			SET status='revoked',start_sequence=NULL,updated_at_milliseconds=$4,updated_at=now()
			WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3
		`, credential.TenantID, target.DomainID, target.SubscriptionID, revocation.RevokedAtMilliseconds); err != nil {
			return relay.TenantMembershipRevocationResult{}, fmt.Errorf("revoke tenant relay subscription: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO relay_tenant_membership_revocation_items
			(tenant_id,retry_id,ordinal,domain_id,subscription_id,member_id)
			VALUES ($1,$2,$3,$4,$5,$6)
		`, credential.TenantID, revocation.RetryID, ordinal, target.DomainID, target.SubscriptionID, target.MemberID); err != nil {
			return relay.TenantMembershipRevocationResult{}, fmt.Errorf("insert tenant membership revocation item: %w", err)
		}
		if err := insertDataPlaneAudit(ctx, tx, credential.TenantID, &target.DomainID, &target.SubscriptionID, &target.MemberID, "tenant_membership_revoked", revocation.RevokedAtMilliseconds); err != nil {
			return relay.TenantMembershipRevocationResult{}, err
		}
	}
	return relay.TenantMembershipRevocationResult{
		Acceptance: relay.AcceptanceAccepted, RetryID: revocation.RetryID,
		RevokedAtMilliseconds: revocation.RevokedAtMilliseconds,
		Memberships:           append([]relay.TenantMembershipRevocationItem(nil), revocation.Memberships...),
	}, nil
}

func loadTenantMembershipRevocationItems(
	ctx context.Context,
	q relayQuerier,
	tenantID, retryID uuid.UUID,
) ([]relay.TenantMembershipRevocationItem, error) {
	rows, err := q.Query(ctx, `
		SELECT domain_id,subscription_id,member_id
		FROM relay_tenant_membership_revocation_items
		WHERE tenant_id=$1 AND retry_id=$2
		ORDER BY ordinal
	`, tenantID, retryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]relay.TenantMembershipRevocationItem, 0)
	for rows.Next() {
		var item relay.TenantMembershipRevocationItem
		if err := rows.Scan(&item.DomainID, &item.SubscriptionID, &item.MemberID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func tenantMembershipRevocationItemsEqual(left, right []relay.TenantMembershipRevocationItem) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (s *RelayStore) ChangeSubscriptionStatus(ctx context.Context, credential relay.AdministrationCredential, subscriptionID uuid.UUID, request relay.SubscriptionStatusChangeRequest) (relay.SubscriptionStatusChangeResponse, error) {
	if subscriptionID == uuid.Nil {
		return relay.SubscriptionStatusChangeResponse{}, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription ID is invalid")
	}
	if err := request.Validate(); err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	response, err := s.changeSubscriptionStatusInTransaction(ctx, tx, credential, subscriptionID, request)
	if err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	return response, nil
}

func (s *RelayStore) changeSubscriptionStatusInTransaction(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.AdministrationCredential,
	subscriptionID uuid.UUID,
	request relay.SubscriptionStatusChangeRequest,
) (relay.SubscriptionStatusChangeResponse, error) {
	if subscriptionID == uuid.Nil {
		return relay.SubscriptionStatusChangeResponse{}, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription ID is invalid")
	}
	if err := request.Validate(); err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE")
	if err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	if err := domain.Authorize(credential); err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	var storedSubscriptionID uuid.UUID
	var storedStatus relay.SubscriptionStatus
	var storedChanged int64
	var storedStart *int64
	err = tx.QueryRow(ctx, `SELECT subscription_id,status,changed_at_milliseconds,result_start_sequence FROM relay_subscription_status_changes WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3 FOR UPDATE`, credential.TenantID, credential.DomainID, request.RetryID).Scan(&storedSubscriptionID, &storedStatus, &storedChanged, &storedStart)
	if err == nil {
		if storedSubscriptionID != subscriptionID || storedStatus != request.Status || storedChanged != request.ChangedAtMilliseconds {
			return relay.SubscriptionStatusChangeResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription status retry ID was reused")
		}
		subscription, _, found, loadErr := loadSubscription(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "")
		if loadErr != nil || !found {
			return relay.SubscriptionStatusChangeResponse{}, loadErr
		}
		subscription.Status = storedStatus
		subscription.StartCursor = cursorFromSequence(storedStart)
		subscription.UpdatedAtMilliseconds = storedChanged
		return relay.SubscriptionStatusChangeResponse{Acceptance: relay.AcceptanceDuplicate, RetryID: request.RetryID, Subscription: subscription}, nil
	}
	if err != pgx.ErrNoRows {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	subscription, _, found, err := loadSubscription(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "FOR UPDATE")
	if err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	if !found || subscription.Status == relay.SubscriptionRevoked {
		return relay.SubscriptionStatusChangeResponse{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "active subscription was not found")
	}
	if request.ChangedAtMilliseconds < subscription.CreatedAtMilliseconds || request.ChangedAtMilliseconds < subscription.UpdatedAtMilliseconds {
		return relay.SubscriptionStatusChangeResponse{}, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription status change is out of order")
	}
	var startSequence *int64
	if request.Status == relay.SubscriptionRebootstrapRequired {
		startSequence, err = latestActivatedCheckpointStart(ctx, tx, credential.TenantID, credential.DomainID)
		if err != nil {
			return relay.SubscriptionStatusChangeResponse{}, err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE relay_subscriptions SET status=$4,start_sequence=$5,updated_at_milliseconds=$6,updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3`, credential.TenantID, credential.DomainID, subscriptionID, request.Status, startSequence, request.ChangedAtMilliseconds)
	if err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO relay_subscription_status_changes (tenant_id,domain_id,retry_id,subscription_id,status,changed_at_milliseconds,result_start_sequence) VALUES ($1,$2,$3,$4,$5,$6,$7)`, credential.TenantID, credential.DomainID, request.RetryID, subscriptionID, request.Status, request.ChangedAtMilliseconds, startSequence)
	if err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	subscription.Status = request.Status
	subscription.StartCursor = cursorFromSequence(startSequence)
	subscription.UpdatedAtMilliseconds = request.ChangedAtMilliseconds
	if err := insertDataPlaneAudit(ctx, tx, credential.TenantID, &credential.DomainID, &subscriptionID, nil, "subscription_status_changed", request.ChangedAtMilliseconds); err != nil {
		return relay.SubscriptionStatusChangeResponse{}, err
	}
	return relay.SubscriptionStatusChangeResponse{Acceptance: relay.AcceptanceAccepted, RetryID: request.RetryID, Subscription: subscription}, nil
}

func loadSubscription(ctx context.Context, q relayQuerier, tenantID, domainID, subscriptionID uuid.UUID, lock string) (relay.Subscription, uuid.UUID, bool, error) {
	var subscription relay.Subscription
	var retryID uuid.UUID
	var startSequence *int64
	err := q.QueryRow(ctx, `SELECT version,create_retry_id,status,start_sequence,created_at_milliseconds,updated_at_milliseconds FROM relay_subscriptions WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3 `+lock, tenantID, domainID, subscriptionID).Scan(&subscription.Version, &retryID, &subscription.Status, &startSequence, &subscription.CreatedAtMilliseconds, &subscription.UpdatedAtMilliseconds)
	if err == pgx.ErrNoRows {
		return relay.Subscription{}, uuid.Nil, false, nil
	}
	if err != nil {
		return relay.Subscription{}, uuid.Nil, false, err
	}
	subscription.TenantID = tenantID
	subscription.DomainID = domainID
	subscription.SubscriptionID = subscriptionID
	subscription.StartCursor = cursorFromSequence(startSequence)
	if err := subscription.Validate(); err != nil {
		return relay.Subscription{}, uuid.Nil, false, err
	}
	return subscription, retryID, true, nil
}

func cursorFromSequence(sequence *int64) *string {
	if sequence == nil {
		return nil
	}
	value := relay.EncodeCursor(uint64(*sequence))
	return &value
}

func sequenceFromCursor(cursor *string) *int64 {
	if cursor == nil {
		return nil
	}
	sequence, err := relay.DecodeCursor(*cursor)
	if err != nil {
		return nil
	}
	value := int64(sequence)
	return &value
}

func latestActivatedCheckpointStart(ctx context.Context, q relayQuerier, tenantID, domainID uuid.UUID) (*int64, error) {
	var sequence *int64
	err := q.QueryRow(ctx, `SELECT start_sequence FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND state='activated' ORDER BY activation_ordinal DESC LIMIT 1`, tenantID, domainID).Scan(&sequence)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load latest activated checkpoint: %w", err)
	}
	return sequence, nil
}

func loadSubscriptionStatus(ctx context.Context, q relayQuerier, tenantID, domainID, subscriptionID uuid.UUID, lock string) (relay.SubscriptionStatus, error) {
	var status relay.SubscriptionStatus
	err := q.QueryRow(ctx, `SELECT status FROM relay_subscriptions WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3 `+lock, tenantID, domainID, subscriptionID).Scan(&status)
	if err == pgx.ErrNoRows {
		return "", relay.NewProtocolError(relay.CodeSubscriptionNotFound, "subscription was not found")
	}
	return status, err
}

func loadActiveMemberSubscription(ctx context.Context, q relayQuerier, tenantID, domainID, memberID uuid.UUID, lock string) (uuid.UUID, error) {
	var subscriptionID uuid.UUID
	var status relay.SubscriptionStatus
	err := q.QueryRow(ctx, `SELECT m.subscription_id,s.status FROM relay_members m JOIN relay_subscriptions s USING (tenant_id,domain_id,subscription_id) WHERE m.tenant_id=$1 AND m.domain_id=$2 AND m.member_id=$3 `+lock, tenantID, domainID, memberID).Scan(&subscriptionID, &status)
	if err == pgx.ErrNoRows {
		return uuid.Nil, relay.NewProtocolError(relay.CodeMemberNotFound, "member subscription was not found")
	}
	if err != nil {
		return uuid.Nil, err
	}
	if status != relay.SubscriptionActive {
		return uuid.Nil, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription is not active")
	}
	return subscriptionID, nil
}

func (s *RelayStore) GetTenantStatus(ctx context.Context, credential relay.TenantCredential) (relay.TenantStatus, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.TenantStatus{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenant, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE")
	if err != nil {
		return relay.TenantStatus{}, err
	}
	if err := tenant.Authorize(credential); err != nil {
		return relay.TenantStatus{}, err
	}
	status := relay.TenantStatus{TenantID: credential.TenantID, Quota: relay.TenantQuota{
		MaximumDomainCount:               tenant.MaximumDomainCount,
		MaximumAggregateMessageCount:     tenant.MaximumAggregateMessageCount,
		MaximumAggregateMessageByteCount: tenant.MaximumAggregateMessageByteCount,
		MaximumAggregateBlobCount:        tenant.MaximumAggregateBlobCount,
		MaximumAggregateBlobByteCount:    tenant.MaximumAggregateBlobByteCount,
	}}
	err = tx.QueryRow(ctx, `SELECT domain_count,message_count,aggregate_message_byte_count,blob_count,aggregate_blob_byte_count,reserved_blob_count,reserved_blob_byte_count FROM relay_tenants WHERE tenant_id=$1`, credential.TenantID).Scan(&status.DomainCount, &status.AggregateMessageCount, &status.AggregateMessageByteCount, &status.AggregateBlobCount, &status.AggregateBlobByteCount, &status.ReservedBlobCount, &status.ReservedBlobByteCount)
	if err != nil {
		return relay.TenantStatus{}, err
	}
	return status, nil
}

func (s *RelayStore) GetDomainStatus(ctx context.Context, credential relay.AdministrationCredential) (relay.DomainStatus, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.DomainStatus{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.DomainStatus{}, err
	}
	domain, messageCount, messageBytes, blobCount, blobBytes, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR SHARE")
	if err != nil {
		return relay.DomainStatus{}, err
	}
	if err := domain.Authorize(credential); err != nil {
		return relay.DomainStatus{}, err
	}
	status := relay.DomainStatus{
		TenantID: credential.TenantID, DomainID: credential.DomainID,
		MessageCount: int64(messageCount), MessageByteCount: messageBytes,
		BlobCount: int64(blobCount), BlobByteCount: blobBytes,
		Quota: relay.DomainQuota{
			MaximumMessageCount:     domain.MaximumMessageCount,
			MaximumMessageByteCount: domain.MaximumMessageByteCount,
			MaximumBlobCount:        domain.MaximumBlobCount,
			MaximumBlobByteCount:    domain.MaximumBlobByteCount,
		},
	}
	if err := tx.QueryRow(ctx, `SELECT reserved_blob_count,reserved_blob_byte_count FROM relay_domains WHERE tenant_id=$1 AND domain_id=$2`, credential.TenantID, credential.DomainID).Scan(&status.ReservedBlobCount, &status.ReservedBlobByteCount); err != nil {
		return relay.DomainStatus{}, err
	}
	err = tx.QueryRow(ctx, `SELECT count(*) FROM relay_subscriptions WHERE tenant_id=$1 AND domain_id=$2 AND status='active'`, credential.TenantID, credential.DomainID).Scan(&status.ActiveSubscriptionCount)
	if err != nil {
		return relay.DomainStatus{}, err
	}
	var oldest *int64
	if err := tx.QueryRow(ctx, `SELECT min(domain_sequence) FROM relay_messages WHERE tenant_id=$1 AND domain_id=$2`, credential.TenantID, credential.DomainID).Scan(&oldest); err != nil {
		return relay.DomainStatus{}, err
	}
	if oldest != nil {
		positionBefore := *oldest - 1
		status.OldestUncollectedCursor = cursorFromSequence(&positionBefore)
	}
	var latestCheckpointID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT checkpoint_id FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND state='activated' ORDER BY activation_ordinal DESC LIMIT 1`, credential.TenantID, credential.DomainID).Scan(&latestCheckpointID)
	if err == nil {
		status.LatestActivatedCheckpointID = &latestCheckpointID
	} else if err != pgx.ErrNoRows {
		return relay.DomainStatus{}, err
	}
	return status, nil
}
