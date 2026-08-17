package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type RelayStore struct {
	pool               *pgxpool.Pool
	blobUploadTTL      time.Duration
	checkpointFenceTTL time.Duration
}

func NewRelayStore(pool *pgxpool.Pool, durations ...time.Duration) *RelayStore {
	uploadTTL := 7 * 24 * time.Hour
	fenceTTL := time.Duration(relay.DefaultCheckpointFenceLifetimeMilliseconds) * time.Millisecond
	if len(durations) > 0 && durations[0] > 0 {
		uploadTTL = durations[0]
	}
	if len(durations) > 1 && durations[1] >= time.Duration(relay.MinimumCheckpointFenceLifetimeMilliseconds)*time.Millisecond && durations[1] <= time.Duration(relay.MaximumCheckpointFenceLifetimeMilliseconds)*time.Millisecond {
		fenceTTL = durations[1]
	}
	return &RelayStore{pool: pool, blobUploadTTL: uploadTTL, checkpointFenceTTL: fenceTTL}
}

func (s *RelayStore) CreateDomain(
	ctx context.Context,
	registration relay.DomainRegistration,
	initialMember relay.MemberRegistration,
) (relay.Acceptance, error) {
	if err := registration.Validate(); err != nil {
		return "", err
	}
	if err := initialMember.Validate(); err != nil {
		return "", err
	}
	if initialMember.TenantID != registration.TenantID ||
		initialMember.DomainID != registration.DomainID ||
		initialMember.CreatedAtMilliseconds < registration.CreatedAtMilliseconds {
		return "", relay.NewProtocolError(
			relay.CodeWrongScope,
			"initial member belongs to another domain",
		)
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", fmt.Errorf("begin relay domain creation: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	acceptance, err := createRelayDomain(ctx, transaction, registration, initialMember)
	if err != nil {
		return "", err
	}
	if acceptance == relay.AcceptanceDuplicate {
		return acceptance, nil
	}
	if err := transaction.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit relay domain creation: %w", err)
	}
	return acceptance, nil
}

func createRelayDomain(
	ctx context.Context,
	transaction pgx.Tx,
	registration relay.DomainRegistration,
	initialMember relay.MemberRegistration,
) (relay.Acceptance, error) {
	result, err := transaction.Exec(ctx, `
		INSERT INTO relay_domains (
			tenant_id, domain_id, version, administration_digest,
			created_at_milliseconds, maximum_message_count,
			maximum_message_byte_count, maximum_blob_count,
			maximum_blob_byte_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, domain_id) DO NOTHING
	`, registration.TenantID, registration.DomainID, registration.Version,
		registration.AdministrationDigest, registration.CreatedAtMilliseconds,
		registration.MaximumMessageCount, registration.MaximumMessageByteCount,
		registration.MaximumBlobCount, registration.MaximumBlobByteCount)
	if err != nil {
		return "", fmt.Errorf("insert relay domain: %w", err)
	}
	if result.RowsAffected() == 0 {
		existing, _, _, _, _, _, err := loadRelayDomain(
			ctx,
			transaction,
			registration.TenantID,
			registration.DomainID,
			"FOR UPDATE",
		)
		if err != nil {
			return "", err
		}
		member, found, err := loadRelayMember(
			ctx,
			transaction,
			registration.TenantID,
			registration.DomainID,
			initialMember.MemberID,
			"FOR UPDATE",
		)
		if err != nil {
			return "", err
		}
		if existing == registration && found && memberEqual(member, initialMember) {
			return relay.AcceptanceDuplicate, nil
		}
		return "", relay.NewProtocolError(
			relay.CodeDomainCollision,
			"domain ID was reused",
		)
	}
	if err := insertRelayMember(ctx, transaction, initialMember); err != nil {
		return "", err
	}
	if err := insertRelayAudit(
		ctx,
		transaction,
		registration.TenantID,
		registration.DomainID,
		nil,
		nil,
		"domain_created",
		registration.CreatedAtMilliseconds,
	); err != nil {
		return "", err
	}
	if err := insertRelayAudit(
		ctx,
		transaction,
		registration.TenantID,
		registration.DomainID,
		&initialMember.MemberID,
		nil,
		"member_created",
		initialMember.CreatedAtMilliseconds,
	); err != nil {
		return "", err
	}
	return relay.AcceptanceAccepted, nil
}

func (s *RelayStore) CreateMember(
	ctx context.Context,
	credential relay.AdministrationCredential,
	registration relay.MemberRegistration,
	nowMilliseconds int64,
) (relay.Acceptance, error) {
	if err := registration.Validate(); err != nil {
		return "", err
	}
	if registration.CreatedAtMilliseconds > nowMilliseconds {
		return "", relay.NewProtocolError(relay.CodeInvalidMember, "member starts in the future")
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", fmt.Errorf("begin relay member creation: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	domain, _, _, _, _, _, err := loadRelayDomain(
		ctx, transaction, credential.TenantID, credential.DomainID, "FOR UPDATE",
	)
	if err != nil {
		return "", err
	}
	if err := domain.Authorize(credential); err != nil {
		return "", err
	}
	if registration.TenantID != credential.TenantID ||
		registration.DomainID != credential.DomainID {
		return "", relay.NewProtocolError(relay.CodeWrongScope, "member belongs to another domain")
	}
	existing, found, err := loadRelayMember(
		ctx,
		transaction,
		registration.TenantID,
		registration.DomainID,
		registration.MemberID,
		"FOR UPDATE",
	)
	if err != nil {
		return "", err
	}
	if found {
		if memberEqual(existing, registration) {
			return relay.AcceptanceDuplicate, nil
		}
		return "", relay.NewProtocolError(relay.CodeMemberCollision, "member ID was reused")
	}
	if registration.ExpiresAtMilliseconds != nil &&
		*registration.ExpiresAtMilliseconds <= nowMilliseconds {
		return "", relay.NewProtocolError(
			relay.CodeInvalidMember,
			"member is not currently issuable",
		)
	}
	if err := ensurePostgresMemberCapacity(
		ctx,
		transaction,
		registration.TenantID,
		registration.DomainID,
		nowMilliseconds,
	); err != nil {
		return "", err
	}
	if err := insertRelayMember(ctx, transaction, registration); err != nil {
		return "", err
	}
	if err := insertRelayAudit(
		ctx,
		transaction,
		registration.TenantID,
		registration.DomainID,
		&registration.MemberID,
		nil,
		"member_created",
		nowMilliseconds,
	); err != nil {
		return "", err
	}
	if err := transaction.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit relay member creation: %w", err)
	}
	return relay.AcceptanceAccepted, nil
}

func (s *RelayStore) CreateAdmission(
	ctx context.Context,
	credential relay.AdministrationCredential,
	registration relay.MemberAdmission,
	nowMilliseconds int64,
) (relay.AdmissionCreateResult, error) {
	if err := registration.Validate(); err != nil {
		return relay.AdmissionCreateResult{}, err
	}
	if registration.RevokedAtMilliseconds != nil ||
		registration.ClaimedAtMilliseconds != nil ||
		registration.ClaimedMemberID != nil {
		return relay.AdmissionCreateResult{}, relay.NewProtocolError(
			relay.CodeInvalidAdmission,
			"new admission already has terminal state",
		)
	}
	if registration.CreatedAtMilliseconds > nowMilliseconds ||
		registration.ExpiresAtMilliseconds <= nowMilliseconds {
		return relay.AdmissionCreateResult{}, relay.NewProtocolError(
			relay.CodeInvalidAdmission,
			"admission is not currently issuable",
		)
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.AdmissionCreateResult{}, fmt.Errorf("begin relay admission creation: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	domain, _, _, _, _, _, err := loadRelayDomain(
		ctx, transaction, credential.TenantID, credential.DomainID, "FOR UPDATE",
	)
	if err != nil {
		return relay.AdmissionCreateResult{}, err
	}
	if err := domain.Authorize(credential); err != nil {
		return relay.AdmissionCreateResult{}, err
	}
	if registration.TenantID != credential.TenantID ||
		registration.DomainID != credential.DomainID {
		return relay.AdmissionCreateResult{}, relay.NewProtocolError(
			relay.CodeWrongScope,
			"admission belongs to another domain",
		)
	}
	existing, found, err := loadRelayAdmission(
		ctx,
		transaction,
		registration.TenantID,
		registration.DomainID,
		registration.AdmissionID,
		"FOR UPDATE",
	)
	if err != nil {
		return relay.AdmissionCreateResult{}, err
	}
	if found {
		if admissionCreationEqual(existing, registration) {
			return relay.AdmissionCreateResult{
				Acceptance: relay.AcceptanceDuplicate,
				Admission:  existing,
			}, nil
		}
		return relay.AdmissionCreateResult{}, relay.NewProtocolError(
			relay.CodeAdmissionCollision,
			"admission ID was reused",
		)
	}
	if err := ensurePostgresAdmissionCapacity(
		ctx,
		transaction,
		registration.TenantID,
		registration.DomainID,
		nowMilliseconds,
	); err != nil {
		return relay.AdmissionCreateResult{}, err
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_member_admissions (
			tenant_id, domain_id, admission_id, version,
			authorization_digest, capabilities, created_at_milliseconds,
			expires_at_milliseconds, member_expires_at_milliseconds,
			revoked_at_milliseconds, claimed_at_milliseconds,
			claimed_member_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, registration.TenantID, registration.DomainID,
		registration.AdmissionID, registration.Version,
		registration.AuthorizationDigest,
		capabilityStrings(registration.Capabilities),
		registration.CreatedAtMilliseconds,
		registration.ExpiresAtMilliseconds,
		registration.MemberExpiresAtMilliseconds,
		registration.RevokedAtMilliseconds,
		registration.ClaimedAtMilliseconds,
		registration.ClaimedMemberID); err != nil {
		return relay.AdmissionCreateResult{}, fmt.Errorf("insert relay admission: %w", err)
	}
	if err := insertRelayAdmissionAudit(
		ctx,
		transaction,
		registration.TenantID,
		registration.DomainID,
		registration.AdmissionID,
		nil,
		"admission_created",
		nowMilliseconds,
	); err != nil {
		return relay.AdmissionCreateResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return relay.AdmissionCreateResult{}, fmt.Errorf("commit relay admission creation: %w", err)
	}
	return relay.AdmissionCreateResult{
		Acceptance: relay.AcceptanceAccepted,
		Admission:  registration,
	}, nil
}

func (s *RelayStore) ClaimAdmission(
	ctx context.Context,
	credential relay.AdmissionCredential,
	claim relay.MemberAdmissionClaim,
	nowMilliseconds int64,
) (relay.AdmissionClaimResult, error) {
	if err := claim.Validate(); err != nil {
		return relay.AdmissionClaimResult{}, err
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.AdmissionClaimResult{}, fmt.Errorf(
			"begin relay admission claim: %w",
			err,
		)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, _, _, _, _, _, err := loadRelayDomain(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		"FOR UPDATE",
	); err != nil {
		return relay.AdmissionClaimResult{}, err
	}
	admission, found, err := loadRelayAdmission(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		credential.AdmissionID,
		"FOR UPDATE",
	)
	if err != nil {
		return relay.AdmissionClaimResult{}, err
	}
	if !found {
		return relay.AdmissionClaimResult{}, relay.NewProtocolError(
			relay.CodeAdmissionNotFound,
			"admission was not found",
		)
	}
	if err := admission.VerifyCredential(credential); err != nil {
		return relay.AdmissionClaimResult{}, err
	}
	if admission.ClaimedMemberID != nil {
		member, found, err := loadRelayMember(
			ctx,
			transaction,
			credential.TenantID,
			credential.DomainID,
			*admission.ClaimedMemberID,
			"FOR SHARE",
		)
		if err != nil {
			return relay.AdmissionClaimResult{}, err
		}
		if found && member.MemberID == claim.MemberID &&
			member.AuthorizationDigest == claim.AuthorizationDigest {
			return relay.AdmissionClaimResult{
				Acceptance: relay.AcceptanceDuplicate,
				Member:     member,
			}, nil
		}
		return relay.AdmissionClaimResult{}, relay.NewProtocolError(
			relay.CodeAdmissionClaimed,
			"admission was already claimed",
		)
	}
	if err := admission.RequireActive(nowMilliseconds); err != nil {
		return relay.AdmissionClaimResult{}, err
	}
	if _, found, err := loadRelayMember(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		claim.MemberID,
		"FOR UPDATE",
	); err != nil {
		return relay.AdmissionClaimResult{}, err
	} else if found {
		return relay.AdmissionClaimResult{}, relay.NewProtocolError(
			relay.CodeMemberCollision,
			"member ID was reused",
		)
	}
	if err := ensurePostgresMemberCapacity(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		nowMilliseconds,
	); err != nil {
		return relay.AdmissionClaimResult{}, err
	}
	member := relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              admission.TenantID,
		DomainID:              admission.DomainID,
		MemberID:              claim.MemberID,
		AuthorizationDigest:   claim.AuthorizationDigest,
		Capabilities:          append([]relay.Capability(nil), admission.Capabilities...),
		CreatedAtMilliseconds: nowMilliseconds,
		ExpiresAtMilliseconds: admission.MemberExpiresAtMilliseconds,
	}
	if err := member.Validate(); err != nil {
		return relay.AdmissionClaimResult{}, err
	}
	if err := insertRelayMember(ctx, transaction, member); err != nil {
		return relay.AdmissionClaimResult{}, err
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE relay_member_admissions
		SET claimed_at_milliseconds = $4, claimed_member_id = $5,
		    updated_at = now()
		WHERE tenant_id = $1 AND domain_id = $2 AND admission_id = $3
	`, admission.TenantID, admission.DomainID, admission.AdmissionID,
		nowMilliseconds, member.MemberID); err != nil {
		return relay.AdmissionClaimResult{}, fmt.Errorf(
			"record relay admission claim: %w",
			err,
		)
	}
	if err := insertRelayAudit(
		ctx,
		transaction,
		member.TenantID,
		member.DomainID,
		&member.MemberID,
		nil,
		"member_created",
		nowMilliseconds,
	); err != nil {
		return relay.AdmissionClaimResult{}, err
	}
	if err := insertRelayAdmissionAudit(
		ctx,
		transaction,
		admission.TenantID,
		admission.DomainID,
		admission.AdmissionID,
		&member.MemberID,
		"admission_claimed",
		nowMilliseconds,
	); err != nil {
		return relay.AdmissionClaimResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return relay.AdmissionClaimResult{}, fmt.Errorf(
			"commit relay admission claim: %w",
			err,
		)
	}
	return relay.AdmissionClaimResult{
		Acceptance: relay.AcceptanceAccepted,
		Member:     member,
	}, nil
}

func (s *RelayStore) RevokeAdmission(
	ctx context.Context,
	credential relay.AdministrationCredential,
	admissionID uuid.UUID,
	nowMilliseconds int64,
) (relay.Acceptance, error) {
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", fmt.Errorf("begin relay admission revocation: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	domain, _, _, _, _, _, err := loadRelayDomain(
		ctx, transaction, credential.TenantID, credential.DomainID, "FOR SHARE",
	)
	if err != nil {
		return "", err
	}
	if err := domain.Authorize(credential); err != nil {
		return "", err
	}
	admission, found, err := loadRelayAdmission(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		admissionID,
		"FOR UPDATE",
	)
	if err != nil {
		return "", err
	}
	if !found {
		return "", relay.NewProtocolError(
			relay.CodeAdmissionNotFound,
			"admission was not found",
		)
	}
	if admission.ClaimedMemberID != nil {
		return "", relay.NewProtocolError(
			relay.CodeAdmissionClaimed,
			"claimed admission cannot be revoked",
		)
	}
	if admission.RevokedAtMilliseconds != nil {
		return relay.AcceptanceDuplicate, nil
	}
	if nowMilliseconds < admission.CreatedAtMilliseconds {
		return "", relay.NewProtocolError(
			relay.CodeInvalidAdmission,
			"revocation precedes admission",
		)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE relay_member_admissions
		SET revoked_at_milliseconds = $4, updated_at = now()
		WHERE tenant_id = $1 AND domain_id = $2 AND admission_id = $3
	`, credential.TenantID, credential.DomainID, admissionID,
		nowMilliseconds); err != nil {
		return "", fmt.Errorf("revoke relay admission: %w", err)
	}
	if err := insertRelayAdmissionAudit(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		admissionID,
		nil,
		"admission_revoked",
		nowMilliseconds,
	); err != nil {
		return "", err
	}
	if err := transaction.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit relay admission revocation: %w", err)
	}
	return relay.AcceptanceAccepted, nil
}

func (s *RelayStore) RevokeMember(
	ctx context.Context,
	credential relay.AdministrationCredential,
	memberID uuid.UUID,
	nowMilliseconds int64,
) (relay.Acceptance, error) {
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", fmt.Errorf("begin relay member revocation: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	domain, _, _, _, _, _, err := loadRelayDomain(
		ctx, transaction, credential.TenantID, credential.DomainID, "FOR SHARE",
	)
	if err != nil {
		return "", err
	}
	if err := domain.Authorize(credential); err != nil {
		return "", err
	}
	member, found, err := loadRelayMember(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		memberID,
		"FOR UPDATE",
	)
	if err != nil {
		return "", err
	}
	if !found {
		return "", relay.NewProtocolError(relay.CodeMemberNotFound, "member was not found")
	}
	if member.RevokedAtMilliseconds != nil {
		return relay.AcceptanceDuplicate, nil
	}
	if nowMilliseconds < member.CreatedAtMilliseconds {
		return "", relay.NewProtocolError(relay.CodeInvalidMember, "revocation precedes membership")
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE relay_members
		SET revoked_at_milliseconds = $4, updated_at = now()
		WHERE tenant_id = $1 AND domain_id = $2 AND member_id = $3
	`, credential.TenantID, credential.DomainID, memberID, nowMilliseconds); err != nil {
		return "", fmt.Errorf("revoke relay member: %w", err)
	}
	if err := insertRelayAudit(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		&memberID,
		nil,
		"member_revoked",
		nowMilliseconds,
	); err != nil {
		return "", err
	}
	if err := transaction.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit relay member revocation: %w", err)
	}
	return relay.AcceptanceAccepted, nil
}

func (s *RelayStore) Publish(
	ctx context.Context,
	credential relay.Credential,
	envelope relay.Envelope,
	nowMilliseconds int64,
) (relay.PublishResult, error) {
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.PublishResult{}, fmt.Errorf("begin relay publish: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	tenant, err := loadRelayTenant(ctx, transaction, credential.TenantID, "FOR UPDATE")
	if err != nil {
		return relay.PublishResult{}, err
	}
	domain, messageCount, messageByteCount, _, _, lastSequence, err := loadRelayDomain(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		"FOR UPDATE",
	)
	if err != nil {
		return relay.PublishResult{}, err
	}
	member, found, err := loadRelayMember(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		credential.MemberID,
		"FOR SHARE",
	)
	if err != nil {
		return relay.PublishResult{}, err
	}
	if !found {
		return relay.PublishResult{}, relay.NewProtocolError(
			relay.CodeMemberNotFound,
			"member was not found",
		)
	}
	if err := member.Authorize(
		credential, relay.CapabilityPublishMessage, nowMilliseconds,
	); err != nil {
		return relay.PublishResult{}, err
	}
	publisherSubscriptionID, err := loadActiveMemberSubscription(
		ctx, transaction, credential.TenantID, credential.DomainID,
		credential.MemberID, "FOR SHARE",
	)
	if err != nil {
		return relay.PublishResult{}, err
	}
	if err := envelope.ValidateForPublish(credential); err != nil {
		return relay.PublishResult{}, err
	}
	existing, found, err := loadRelayMessage(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		envelope.MessageID,
		"FOR UPDATE",
	)
	if err != nil {
		return relay.PublishResult{}, err
	}
	if found {
		if existing.Envelope == envelope &&
			existing.Envelope.PublisherMemberID == credential.MemberID {
			return relay.PublishResult{
				Acceptance: relay.AcceptanceDuplicate,
				Sequence:   existing.Sequence,
			}, nil
		}
		return relay.PublishResult{}, relay.NewProtocolError(
			relay.CodeMessageCollision,
			"message ID was reused with different content",
		)
	}
	var tombstoneMember uuid.UUID
	var tombstoneDigest string
	var tombstoneSequence int64
	tombstoneErr := transaction.QueryRow(ctx, `SELECT publisher_member_id,envelope_digest,domain_sequence FROM relay_checkpoint_fence_message_tombstones WHERE tenant_id=$1 AND domain_id=$2 AND message_id=$3`, credential.TenantID, credential.DomainID, envelope.MessageID).Scan(&tombstoneMember, &tombstoneDigest, &tombstoneSequence)
	if tombstoneErr == nil {
		digest, digestErr := envelope.ReferenceDigest()
		if digestErr != nil {
			return relay.PublishResult{}, digestErr
		}
		if tombstoneMember == credential.MemberID && tombstoneDigest == digest {
			return relay.PublishResult{Acceptance: relay.AcceptanceDuplicate, Sequence: uint64(tombstoneSequence)}, nil
		}
		return relay.PublishResult{}, relay.NewProtocolError(relay.CodeMessageCollision, "message ID was reused with different content")
	}
	if tombstoneErr != pgx.ErrNoRows {
		return relay.PublishResult{}, tombstoneErr
	}
	if err := postgresFenceAllowsWrite(ctx, transaction, credential.TenantID, credential.DomainID, publisherSubscriptionID, nowMilliseconds); err != nil {
		return relay.PublishResult{}, err
	}
	fenceID, err := postgresActiveFenceForSubscription(ctx, transaction, credential.TenantID, credential.DomainID, publisherSubscriptionID)
	if err != nil {
		return relay.PublishResult{}, err
	}
	if messageCount >= domain.MaximumMessageCount {
		return relay.PublishResult{}, relay.NewProtocolError(
			relay.CodeDomainFull,
			"domain reached its message limit",
		)
	}
	ciphertextByteCount, err := envelope.CiphertextByteCount()
	if err != nil {
		return relay.PublishResult{}, err
	}
	envelopeDigest, err := envelope.ReferenceDigest()
	if err != nil {
		return relay.PublishResult{}, err
	}
	if ciphertextByteCount > domain.MaximumMessageByteCount-messageByteCount {
		return relay.PublishResult{}, relay.NewProtocolError(
			relay.CodeDomainFull,
			"domain reached its message-byte limit",
		)
	}
	var tenantMessageCount int
	var tenantMessageByteCount int64
	if err := transaction.QueryRow(ctx, `SELECT message_count,aggregate_message_byte_count FROM relay_tenants WHERE tenant_id=$1`, credential.TenantID).Scan(&tenantMessageCount, &tenantMessageByteCount); err != nil {
		return relay.PublishResult{}, fmt.Errorf("load tenant message counters: %w", err)
	}
	if tenantMessageCount >= tenant.MaximumAggregateMessageCount ||
		ciphertextByteCount > tenant.MaximumAggregateMessageByteCount-tenantMessageByteCount {
		return relay.PublishResult{}, relay.NewProtocolError(relay.CodeTenantFull, "tenant reached its aggregate message quota")
	}
	sequence := lastSequence + 1
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_messages (
			tenant_id, domain_id, domain_sequence, message_id,
			publisher_member_id, publisher_subscription_id, version, algorithm, key_epoch,
			created_at_milliseconds, nonce, ciphertext, authentication_tag,
			ciphertext_byte_count, checkpoint_fence_id, envelope_digest
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`, envelope.TenantID, envelope.DomainID, sequence, envelope.MessageID,
		envelope.PublisherMemberID, publisherSubscriptionID, envelope.Version, envelope.Algorithm,
		int64(envelope.KeyEpoch), envelope.CreatedAtMilliseconds,
		envelope.Nonce, envelope.Ciphertext, envelope.AuthenticationTag,
		ciphertextByteCount, fenceID, envelopeDigest); err != nil {
		return relay.PublishResult{}, fmt.Errorf("insert relay message: %w", err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE relay_tenants SET message_count=message_count+1,aggregate_message_byte_count=aggregate_message_byte_count+$2,updated_at=now() WHERE tenant_id=$1`, credential.TenantID, ciphertextByteCount); err != nil {
		return relay.PublishResult{}, fmt.Errorf("advance tenant message counters: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE relay_domains
		SET message_count = message_count + 1,
		    message_byte_count = message_byte_count + $4,
		    last_sequence = $3
		WHERE tenant_id = $1 AND domain_id = $2
	`, credential.TenantID, credential.DomainID, sequence,
		ciphertextByteCount); err != nil {
		return relay.PublishResult{}, fmt.Errorf("advance relay domain sequence: %w", err)
	}
	if err := insertRelayAudit(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		&credential.MemberID,
		&envelope.MessageID,
		"message_published",
		nowMilliseconds,
	); err != nil {
		return relay.PublishResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return relay.PublishResult{}, fmt.Errorf("commit relay publish: %w", err)
	}
	return relay.PublishResult{
		Acceptance: relay.AcceptanceAccepted,
		Sequence:   uint64(sequence),
	}, nil
}

func (s *RelayStore) Fetch(
	ctx context.Context,
	credential relay.Credential,
	afterSequence uint64,
	limit int,
	nowMilliseconds int64,
) (relay.FetchResult, error) {
	if limit <= 0 || limit > relay.MaximumPageSize ||
		afterSequence > relay.MaximumSequence {
		return relay.FetchResult{}, relay.NewProtocolError(
			relay.CodeInvalidCursor,
			"page limit is invalid",
		)
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.FetchResult{}, fmt.Errorf("begin relay fetch: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, transaction, credential.TenantID, "FOR UPDATE"); err != nil {
		return relay.FetchResult{}, err
	}
	_, _, _, _, _, highWatermark, err := loadRelayDomain(
		ctx, transaction, credential.TenantID, credential.DomainID, "FOR UPDATE",
	)
	if err != nil {
		return relay.FetchResult{}, err
	}
	if err := expirePostgresFence(ctx, transaction, credential.TenantID, credential.DomainID, nowMilliseconds); err != nil {
		return relay.FetchResult{}, err
	}
	member, found, err := loadRelayMember(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		credential.MemberID,
		"FOR SHARE",
	)
	if err != nil {
		return relay.FetchResult{}, err
	}
	if !found {
		return relay.FetchResult{}, relay.NewProtocolError(
			relay.CodeMemberNotFound,
			"member was not found",
		)
	}
	if err := member.Authorize(
		credential, relay.CapabilityFetchMessage, nowMilliseconds,
	); err != nil {
		return relay.FetchResult{}, err
	}
	subscriptionID, err := loadActiveMemberSubscription(
		ctx, transaction, credential.TenantID, credential.DomainID,
		credential.MemberID, "FOR SHARE",
	)
	if err != nil {
		return relay.FetchResult{}, err
	}
	var subscriptionStart *int64
	if err := transaction.QueryRow(ctx, `SELECT start_sequence FROM relay_subscriptions WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3`, credential.TenantID, credential.DomainID, subscriptionID).Scan(&subscriptionStart); err != nil {
		return relay.FetchResult{}, fmt.Errorf("load subscription start cursor: %w", err)
	}
	if subscriptionStart != nil && uint64(*subscriptionStart) > afterSequence {
		afterSequence = uint64(*subscriptionStart)
	}
	var activeFenceBoundary int64
	if err := transaction.QueryRow(ctx, `SELECT boundary_sequence FROM relay_checkpoint_fences WHERE tenant_id=$1 AND domain_id=$2 AND status='active' LIMIT 1`, credential.TenantID, credential.DomainID).Scan(&activeFenceBoundary); err == nil {
		if activeFenceBoundary < highWatermark {
			highWatermark = activeFenceBoundary
		}
	} else if err != pgx.ErrNoRows {
		return relay.FetchResult{}, err
	}
	rows, err := transaction.Query(ctx, `
		SELECT domain_sequence, message_id, publisher_member_id,
		       version, algorithm, key_epoch, created_at_milliseconds,
		       nonce, ciphertext, authentication_tag
		FROM relay_messages
		WHERE tenant_id = $1 AND domain_id = $2
		  AND domain_sequence > $3 AND domain_sequence <= $4
		  AND publisher_subscription_id <> $5
		  AND (checkpoint_fence_id IS NULL OR EXISTS (
		      SELECT 1 FROM relay_checkpoint_fences f
		      WHERE f.tenant_id=relay_messages.tenant_id AND f.domain_id=relay_messages.domain_id
		        AND f.fence_id=relay_messages.checkpoint_fence_id AND f.status='activated'))
		ORDER BY domain_sequence
		LIMIT $6
	`, credential.TenantID, credential.DomainID, int64(afterSequence),
		highWatermark, subscriptionID, limit)
	if err != nil {
		return relay.FetchResult{}, fmt.Errorf("fetch relay messages: %w", err)
	}
	defer rows.Close()
	result := relay.FetchResult{Messages: make([]relay.Message, 0, limit)}
	for rows.Next() {
		message := relay.Message{
			Envelope: relay.Envelope{
				TenantID: credential.TenantID,
				DomainID: credential.DomainID,
			},
		}
		var sequence, keyEpoch int64
		if err := rows.Scan(
			&sequence,
			&message.Envelope.MessageID,
			&message.Envelope.PublisherMemberID,
			&message.Envelope.Version,
			&message.Envelope.Algorithm,
			&keyEpoch,
			&message.Envelope.CreatedAtMilliseconds,
			&message.Envelope.Nonce,
			&message.Envelope.Ciphertext,
			&message.Envelope.AuthenticationTag,
		); err != nil {
			return relay.FetchResult{}, fmt.Errorf("scan relay message: %w", err)
		}
		message.Sequence = uint64(sequence)
		message.Envelope.KeyEpoch = uint64(keyEpoch)
		if err := message.Envelope.Validate(); err != nil {
			return relay.FetchResult{}, fmt.Errorf("stored relay message failed validation: %v", err)
		}
		result.Messages = append(result.Messages, message)
		result.NextSequence = message.Sequence
	}
	if err := rows.Err(); err != nil {
		return relay.FetchResult{}, fmt.Errorf("iterate relay messages: %w", err)
	}
	if len(result.Messages) < limit {
		result.NextSequence = uint64(highWatermark)
		if afterSequence > result.NextSequence {
			result.NextSequence = afterSequence
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return relay.FetchResult{}, fmt.Errorf("commit relay fetch: %w", err)
	}
	return result, nil
}

func (s *RelayStore) Acknowledge(
	ctx context.Context,
	credential relay.Credential,
	messageID uuid.UUID,
	stage relay.AcknowledgmentStage,
	nowMilliseconds int64,
) (relay.AcknowledgmentResult, error) {
	if !stage.Valid() {
		return relay.AcknowledgmentResult{}, relay.NewProtocolError(
			relay.CodeInvalidAcknowledgment,
			"acknowledgment stage is invalid",
		)
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.AcknowledgmentResult{}, fmt.Errorf("begin relay acknowledgment: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, transaction, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.AcknowledgmentResult{}, err
	}
	if _, _, _, _, _, _, err := loadRelayDomain(ctx, transaction, credential.TenantID, credential.DomainID, "FOR SHARE"); err != nil {
		return relay.AcknowledgmentResult{}, err
	}
	member, found, err := loadRelayMember(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		credential.MemberID,
		"FOR SHARE",
	)
	if err != nil {
		return relay.AcknowledgmentResult{}, err
	}
	if !found {
		return relay.AcknowledgmentResult{}, relay.NewProtocolError(
			relay.CodeMemberNotFound,
			"member was not found",
		)
	}
	if err := member.Authorize(
		credential, relay.CapabilityAcknowledgeMessage, nowMilliseconds,
	); err != nil {
		return relay.AcknowledgmentResult{}, err
	}
	subscriptionID, err := loadActiveMemberSubscription(
		ctx, transaction, credential.TenantID, credential.DomainID,
		credential.MemberID, "FOR SHARE",
	)
	if err != nil {
		return relay.AcknowledgmentResult{}, err
	}
	_, found, err = loadRelayMessage(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		messageID,
		"FOR SHARE",
	)
	if err != nil {
		return relay.AcknowledgmentResult{}, err
	}
	if !found {
		return relay.AcknowledgmentResult{}, relay.NewProtocolError(
			relay.CodeMessageNotFound,
			"message was not found",
		)
	}
	var publisherSubscriptionID uuid.UUID
	if err := transaction.QueryRow(ctx, `SELECT publisher_subscription_id FROM relay_messages WHERE tenant_id=$1 AND domain_id=$2 AND message_id=$3`, credential.TenantID, credential.DomainID, messageID).Scan(&publisherSubscriptionID); err != nil {
		return relay.AcknowledgmentResult{}, fmt.Errorf("load message publisher subscription: %w", err)
	}
	if publisherSubscriptionID == subscriptionID {
		return relay.AcknowledgmentResult{}, relay.NewProtocolError(
			relay.CodeInvalidAcknowledgment,
			"publisher cannot acknowledge its message",
		)
	}
	var existing relay.AcknowledgmentStage
	err = transaction.QueryRow(ctx, `
		SELECT stage
		FROM relay_acknowledgments
		WHERE tenant_id = $1 AND domain_id = $2
		  AND message_id = $3 AND subscription_id = $4
		FOR UPDATE
	`, credential.TenantID, credential.DomainID, messageID, subscriptionID).Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return relay.AcknowledgmentResult{}, fmt.Errorf("load relay acknowledgment: %w", err)
	}
	hasExisting := err == nil
	if hasExisting && (existing == stage || existing == relay.AcknowledgmentApplied) {
		return relay.AcknowledgmentResult{
			Acceptance: relay.AcceptanceDuplicate,
			Stage:      existing,
		}, nil
	}
	if stage == relay.AcknowledgmentApplied && !hasExisting {
		return relay.AcknowledgmentResult{}, relay.NewProtocolError(
			relay.CodeInvalidAcknowledgment,
			"applied requires a durable accepted acknowledgment",
		)
	}
	if !hasExisting {
		result, err := transaction.Exec(ctx, `
			INSERT INTO relay_acknowledgments (
				tenant_id, domain_id, message_id, subscription_id, stage,
				accepted_at_milliseconds
			) VALUES ($1, $2, $3, $4, 'accepted', $5)
			ON CONFLICT (tenant_id, domain_id, message_id, subscription_id) DO NOTHING
		`, credential.TenantID, credential.DomainID, messageID,
			subscriptionID, nowMilliseconds)
		if err != nil {
			return relay.AcknowledgmentResult{}, fmt.Errorf("insert relay acknowledgment: %w", err)
		}
		if result.RowsAffected() == 0 {
			if err := transaction.QueryRow(ctx, `
				SELECT stage
				FROM relay_acknowledgments
				WHERE tenant_id = $1 AND domain_id = $2
				  AND message_id = $3 AND subscription_id = $4
				FOR UPDATE
			`, credential.TenantID, credential.DomainID, messageID,
				subscriptionID).Scan(&existing); err != nil {
				return relay.AcknowledgmentResult{}, fmt.Errorf(
					"reload relay acknowledgment: %w",
					err,
				)
			}
			return relay.AcknowledgmentResult{
				Acceptance: relay.AcceptanceDuplicate,
				Stage:      existing,
			}, nil
		}
	} else {
		if _, err := transaction.Exec(ctx, `
			UPDATE relay_acknowledgments
			SET stage = 'applied', applied_at_milliseconds = $5, updated_at = now()
			WHERE tenant_id = $1 AND domain_id = $2
			  AND message_id = $3 AND subscription_id = $4
		`, credential.TenantID, credential.DomainID, messageID,
			subscriptionID, nowMilliseconds); err != nil {
			return relay.AcknowledgmentResult{}, fmt.Errorf("apply relay acknowledgment: %w", err)
		}
	}
	eventType := "message_accepted"
	if stage == relay.AcknowledgmentApplied {
		eventType = "message_applied"
	}
	if err := insertRelayAudit(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		&credential.MemberID,
		&messageID,
		eventType,
		nowMilliseconds,
	); err != nil {
		return relay.AcknowledgmentResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return relay.AcknowledgmentResult{}, fmt.Errorf("commit relay acknowledgment: %w", err)
	}
	return relay.AcknowledgmentResult{
		Acceptance: relay.AcceptanceAccepted,
		Stage:      stage,
	}, nil
}

func (s *RelayStore) PrepareBlobPublish(
	ctx context.Context,
	credential relay.Credential,
	blobID string,
	byteCount int64,
	nowMilliseconds int64,
) error {
	metadata := relay.BlobMetadata{
		TenantID:              credential.TenantID,
		DomainID:              credential.DomainID,
		BlobID:                blobID,
		PublisherMemberID:     credential.MemberID,
		ByteCount:             byteCount,
		CreatedAtMilliseconds: nowMilliseconds,
	}
	if err := metadata.Validate(); err != nil {
		return err
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin relay blob preparation: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	tenant, err := loadRelayTenant(ctx, transaction, credential.TenantID, "FOR SHARE")
	if err != nil {
		return err
	}
	domain, _, _, blobCount, blobByteCount, _, err := loadRelayDomain(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		"FOR SHARE",
	)
	if err != nil {
		return err
	}
	member, found, err := loadRelayMember(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		credential.MemberID,
		"FOR SHARE",
	)
	if err != nil {
		return err
	}
	if !found {
		return relay.NewProtocolError(relay.CodeMemberNotFound, "member was not found")
	}
	if err := member.Authorize(
		credential, relay.CapabilityPublishBlob, nowMilliseconds,
	); err != nil {
		return err
	}
	existing, found, err := loadRelayBlob(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		blobID,
		"FOR SHARE",
	)
	if err != nil {
		return err
	}
	if found {
		if existing.ByteCount == byteCount {
			return nil
		}
		return relay.NewProtocolError(
			relay.CodeBlobCollision,
			"blob ID was reused with a different length",
		)
	}
	if err := ensureRelayBlobCapacity(domain, blobCount, blobByteCount, byteCount); err != nil {
		return err
	}
	var tenantBlobCount int
	var tenantBlobByteCount int64
	if err := transaction.QueryRow(ctx, `SELECT blob_count,aggregate_blob_byte_count FROM relay_tenants WHERE tenant_id=$1`, credential.TenantID).Scan(&tenantBlobCount, &tenantBlobByteCount); err != nil {
		return err
	}
	if tenantBlobCount >= tenant.MaximumAggregateBlobCount || byteCount > tenant.MaximumAggregateBlobByteCount-tenantBlobByteCount {
		return relay.NewProtocolError(relay.CodeTenantFull, "tenant reached its aggregate blob quota")
	}
	return nil
}

func (s *RelayStore) CommitBlobPublish(
	ctx context.Context,
	credential relay.Credential,
	blobID string,
	byteCount int64,
	nowMilliseconds int64,
) (relay.BlobPublishResult, error) {
	metadata := relay.BlobMetadata{
		TenantID:              credential.TenantID,
		DomainID:              credential.DomainID,
		BlobID:                blobID,
		PublisherMemberID:     credential.MemberID,
		ByteCount:             byteCount,
		CreatedAtMilliseconds: nowMilliseconds,
	}
	if err := metadata.Validate(); err != nil {
		return relay.BlobPublishResult{}, err
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.BlobPublishResult{}, fmt.Errorf("begin relay blob commit: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	tenant, err := loadRelayTenant(ctx, transaction, credential.TenantID, "FOR UPDATE")
	if err != nil {
		return relay.BlobPublishResult{}, err
	}
	domain, _, _, blobCount, blobByteCount, _, err := loadRelayDomain(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		"FOR UPDATE",
	)
	if err != nil {
		return relay.BlobPublishResult{}, err
	}
	member, found, err := loadRelayMember(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		credential.MemberID,
		"FOR SHARE",
	)
	if err != nil {
		return relay.BlobPublishResult{}, err
	}
	if !found {
		return relay.BlobPublishResult{}, relay.NewProtocolError(
			relay.CodeMemberNotFound,
			"member was not found",
		)
	}
	if err := member.Authorize(
		credential, relay.CapabilityPublishBlob, nowMilliseconds,
	); err != nil {
		return relay.BlobPublishResult{}, err
	}
	existing, found, err := loadRelayBlob(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		blobID,
		"FOR UPDATE",
	)
	if err != nil {
		return relay.BlobPublishResult{}, err
	}
	if found {
		if existing.ByteCount == byteCount {
			return relay.BlobPublishResult{
				Acceptance: relay.AcceptanceDuplicate,
				ByteCount:  byteCount,
			}, nil
		}
		return relay.BlobPublishResult{}, relay.NewProtocolError(
			relay.CodeBlobCollision,
			"blob ID was reused with a different length",
		)
	}
	subscriptionID, err := loadActiveMemberSubscription(ctx, transaction, credential.TenantID, credential.DomainID, credential.MemberID, "FOR SHARE")
	if err != nil {
		return relay.BlobPublishResult{}, err
	}
	if err := postgresFenceAllowsWrite(ctx, transaction, credential.TenantID, credential.DomainID, subscriptionID, nowMilliseconds); err != nil {
		return relay.BlobPublishResult{}, err
	}
	fenceID, err := postgresActiveFenceForSubscription(ctx, transaction, credential.TenantID, credential.DomainID, subscriptionID)
	if err != nil {
		return relay.BlobPublishResult{}, err
	}
	if err := ensureRelayBlobCapacity(
		domain, blobCount, blobByteCount, byteCount,
	); err != nil {
		return relay.BlobPublishResult{}, err
	}
	var tenantBlobCount int
	var tenantBlobByteCount int64
	if err := transaction.QueryRow(ctx, `SELECT blob_count,aggregate_blob_byte_count FROM relay_tenants WHERE tenant_id=$1`, credential.TenantID).Scan(&tenantBlobCount, &tenantBlobByteCount); err != nil {
		return relay.BlobPublishResult{}, err
	}
	if tenantBlobCount >= tenant.MaximumAggregateBlobCount || byteCount > tenant.MaximumAggregateBlobByteCount-tenantBlobByteCount {
		return relay.BlobPublishResult{}, relay.NewProtocolError(relay.CodeTenantFull, "tenant reached its aggregate blob quota")
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_blobs (
			tenant_id, domain_id, blob_id, publisher_member_id,
			byte_count, created_at_milliseconds, checkpoint_fence_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, metadata.TenantID, metadata.DomainID, metadata.BlobID,
		metadata.PublisherMemberID, metadata.ByteCount,
		metadata.CreatedAtMilliseconds, fenceID); err != nil {
		return relay.BlobPublishResult{}, fmt.Errorf("insert relay blob: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE relay_domains
		SET blob_count = blob_count + 1,
		    blob_byte_count = blob_byte_count + $3
		WHERE tenant_id = $1 AND domain_id = $2
	`, credential.TenantID, credential.DomainID, byteCount); err != nil {
		return relay.BlobPublishResult{}, fmt.Errorf("advance relay blob counters: %w", err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE relay_tenants SET blob_count=blob_count+1,aggregate_blob_byte_count=aggregate_blob_byte_count+$2,updated_at=now() WHERE tenant_id=$1`, credential.TenantID, byteCount); err != nil {
		return relay.BlobPublishResult{}, fmt.Errorf("advance tenant blob counters: %w", err)
	}
	if err := insertRelayBlobAudit(ctx, transaction, metadata); err != nil {
		return relay.BlobPublishResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return relay.BlobPublishResult{}, fmt.Errorf("commit relay blob: %w", err)
	}
	return relay.BlobPublishResult{
		Acceptance: relay.AcceptanceAccepted,
		ByteCount:  byteCount,
	}, nil
}

func (s *RelayStore) GetBlobMetadata(
	ctx context.Context,
	credential relay.Credential,
	blobID string,
	nowMilliseconds int64,
) (relay.BlobMetadata, error) {
	if err := relay.ValidateBlobID(blobID); err != nil {
		return relay.BlobMetadata{}, err
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.BlobMetadata{}, fmt.Errorf("begin relay blob fetch: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, transaction, credential.TenantID, "FOR UPDATE"); err != nil {
		return relay.BlobMetadata{}, err
	}
	if _, _, _, _, _, _, err := loadRelayDomain(ctx, transaction, credential.TenantID, credential.DomainID, "FOR UPDATE"); err != nil {
		return relay.BlobMetadata{}, err
	}
	if err := expirePostgresFence(ctx, transaction, credential.TenantID, credential.DomainID, nowMilliseconds); err != nil {
		return relay.BlobMetadata{}, err
	}
	member, found, err := loadRelayMember(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		credential.MemberID,
		"FOR SHARE",
	)
	if err != nil {
		return relay.BlobMetadata{}, err
	}
	if !found {
		return relay.BlobMetadata{}, relay.NewProtocolError(
			relay.CodeMemberNotFound,
			"member was not found",
		)
	}
	if err := member.Authorize(
		credential, relay.CapabilityFetchBlob, nowMilliseconds,
	); err != nil {
		return relay.BlobMetadata{}, err
	}
	metadata, found, err := loadRelayBlob(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		blobID,
		"FOR SHARE",
	)
	if err != nil {
		return relay.BlobMetadata{}, err
	}
	if !found {
		return relay.BlobMetadata{}, relay.NewProtocolError(
			relay.CodeBlobNotFound,
			"blob was not found",
		)
	}
	var fenceStatus *string
	if err := transaction.QueryRow(ctx, `SELECT f.status FROM relay_blobs b LEFT JOIN relay_checkpoint_fences f ON f.tenant_id=b.tenant_id AND f.domain_id=b.domain_id AND f.fence_id=b.checkpoint_fence_id WHERE b.tenant_id=$1 AND b.domain_id=$2 AND b.blob_id=$3`, credential.TenantID, credential.DomainID, blobID).Scan(&fenceStatus); err != nil {
		return relay.BlobMetadata{}, err
	}
	if fenceStatus != nil && *fenceStatus != string(relay.CheckpointFenceActivated) {
		return relay.BlobMetadata{}, relay.NewProtocolError(relay.CodeBlobNotFound, "blob was not found")
	}
	if err := transaction.Commit(ctx); err != nil {
		return relay.BlobMetadata{}, fmt.Errorf("commit relay blob fetch: %w", err)
	}
	return metadata, nil
}

type relayQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadRelayDomain(
	ctx context.Context,
	querier relayQuerier,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	lockClause string,
) (relay.DomainRegistration, int, int64, int, int64, int64, error) {
	query := `
		SELECT version, administration_digest, created_at_milliseconds,
		       maximum_message_count, maximum_message_byte_count,
		       maximum_blob_count, maximum_blob_byte_count,
		       message_count, message_byte_count, blob_count,
		       blob_byte_count, last_sequence
		FROM relay_domains
		WHERE tenant_id = $1 AND domain_id = $2
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	registration := relay.DomainRegistration{TenantID: tenantID, DomainID: domainID}
	var messageCount, blobCount int
	var messageByteCount, blobByteCount, lastSequence int64
	err := querier.QueryRow(ctx, query, tenantID, domainID).Scan(
		&registration.Version,
		&registration.AdministrationDigest,
		&registration.CreatedAtMilliseconds,
		&registration.MaximumMessageCount,
		&registration.MaximumMessageByteCount,
		&registration.MaximumBlobCount,
		&registration.MaximumBlobByteCount,
		&messageCount,
		&messageByteCount,
		&blobCount,
		&blobByteCount,
		&lastSequence,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return relay.DomainRegistration{}, 0, 0, 0, 0, 0, relay.NewProtocolError(
			relay.CodeDomainNotFound,
			"domain was not found",
		)
	}
	if err != nil {
		return relay.DomainRegistration{}, 0, 0, 0, 0, 0, fmt.Errorf("load relay domain: %w", err)
	}
	if err := registration.Validate(); err != nil {
		return relay.DomainRegistration{}, 0, 0, 0, 0, 0, fmt.Errorf("stored relay domain failed validation: %v", err)
	}
	if messageCount < 0 || messageCount > registration.MaximumMessageCount ||
		messageByteCount < 0 || messageByteCount > registration.MaximumMessageByteCount ||
		blobCount < 0 || blobCount > registration.MaximumBlobCount ||
		blobByteCount < 0 || blobByteCount > registration.MaximumBlobByteCount ||
		lastSequence < int64(messageCount) {
		return relay.DomainRegistration{}, 0, 0, 0, 0, 0, fmt.Errorf("stored relay domain counters are invalid")
	}
	return registration, messageCount, messageByteCount, blobCount, blobByteCount, lastSequence, nil
}

func loadRelayMember(
	ctx context.Context,
	querier relayQuerier,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	memberID uuid.UUID,
	lockClause string,
) (relay.MemberRegistration, bool, error) {
	query := `
		SELECT version, authorization_digest, capabilities,
		       created_at_milliseconds, expires_at_milliseconds,
		       revoked_at_milliseconds
		FROM relay_members
		WHERE tenant_id = $1 AND domain_id = $2 AND member_id = $3
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	registration := relay.MemberRegistration{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: memberID,
	}
	var capabilities []string
	err := querier.QueryRow(ctx, query, tenantID, domainID, memberID).Scan(
		&registration.Version,
		&registration.AuthorizationDigest,
		&capabilities,
		&registration.CreatedAtMilliseconds,
		&registration.ExpiresAtMilliseconds,
		&registration.RevokedAtMilliseconds,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return relay.MemberRegistration{}, false, nil
	}
	if err != nil {
		return relay.MemberRegistration{}, false, fmt.Errorf("load relay member: %w", err)
	}
	registration.Capabilities = make([]relay.Capability, len(capabilities))
	for index, capability := range capabilities {
		registration.Capabilities[index] = relay.Capability(capability)
	}
	if err := registration.Validate(); err != nil {
		return relay.MemberRegistration{}, false, fmt.Errorf("stored relay member failed validation: %v", err)
	}
	return registration, true, nil
}

func loadRelayAdmission(
	ctx context.Context,
	querier relayQuerier,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	admissionID uuid.UUID,
	lockClause string,
) (relay.MemberAdmission, bool, error) {
	query := `
		SELECT version, authorization_digest, capabilities,
		       created_at_milliseconds, expires_at_milliseconds,
		       member_expires_at_milliseconds, revoked_at_milliseconds,
		       claimed_at_milliseconds, claimed_member_id
		FROM relay_member_admissions
		WHERE tenant_id = $1 AND domain_id = $2 AND admission_id = $3
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	registration := relay.MemberAdmission{
		TenantID:    tenantID,
		DomainID:    domainID,
		AdmissionID: admissionID,
	}
	var capabilities []string
	err := querier.QueryRow(ctx, query, tenantID, domainID, admissionID).Scan(
		&registration.Version,
		&registration.AuthorizationDigest,
		&capabilities,
		&registration.CreatedAtMilliseconds,
		&registration.ExpiresAtMilliseconds,
		&registration.MemberExpiresAtMilliseconds,
		&registration.RevokedAtMilliseconds,
		&registration.ClaimedAtMilliseconds,
		&registration.ClaimedMemberID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return relay.MemberAdmission{}, false, nil
	}
	if err != nil {
		return relay.MemberAdmission{}, false, fmt.Errorf(
			"load relay admission: %w",
			err,
		)
	}
	registration.Capabilities = make([]relay.Capability, len(capabilities))
	for index, capability := range capabilities {
		registration.Capabilities[index] = relay.Capability(capability)
	}
	if err := registration.Validate(); err != nil {
		return relay.MemberAdmission{}, false, fmt.Errorf(
			"stored relay admission failed validation: %v",
			err,
		)
	}
	return registration, true, nil
}

func loadRelayMessage(
	ctx context.Context,
	querier relayQuerier,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	messageID uuid.UUID,
	lockClause string,
) (relay.Message, bool, error) {
	query := `
		SELECT domain_sequence, publisher_member_id, version, algorithm,
		       key_epoch, created_at_milliseconds, nonce, ciphertext,
		       authentication_tag
		FROM relay_messages
		WHERE tenant_id = $1 AND domain_id = $2 AND message_id = $3
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	message := relay.Message{
		Envelope: relay.Envelope{
			TenantID:  tenantID,
			DomainID:  domainID,
			MessageID: messageID,
		},
	}
	var sequence, keyEpoch int64
	err := querier.QueryRow(ctx, query, tenantID, domainID, messageID).Scan(
		&sequence,
		&message.Envelope.PublisherMemberID,
		&message.Envelope.Version,
		&message.Envelope.Algorithm,
		&keyEpoch,
		&message.Envelope.CreatedAtMilliseconds,
		&message.Envelope.Nonce,
		&message.Envelope.Ciphertext,
		&message.Envelope.AuthenticationTag,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return relay.Message{}, false, nil
	}
	if err != nil {
		return relay.Message{}, false, fmt.Errorf("load relay message: %w", err)
	}
	message.Sequence = uint64(sequence)
	message.Envelope.KeyEpoch = uint64(keyEpoch)
	if err := message.Envelope.Validate(); err != nil {
		return relay.Message{}, false, fmt.Errorf("stored relay message failed validation: %v", err)
	}
	return message, true, nil
}

func loadRelayBlob(
	ctx context.Context,
	querier relayQuerier,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	blobID string,
	lockClause string,
) (relay.BlobMetadata, bool, error) {
	query := `
		SELECT publisher_member_id, byte_count, created_at_milliseconds
		FROM relay_blobs
		WHERE tenant_id = $1 AND domain_id = $2 AND blob_id = $3
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	metadata := relay.BlobMetadata{
		TenantID: tenantID,
		DomainID: domainID,
		BlobID:   blobID,
	}
	err := querier.QueryRow(ctx, query, tenantID, domainID, blobID).Scan(
		&metadata.PublisherMemberID,
		&metadata.ByteCount,
		&metadata.CreatedAtMilliseconds,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return relay.BlobMetadata{}, false, nil
	}
	if err != nil {
		return relay.BlobMetadata{}, false, fmt.Errorf("load relay blob: %w", err)
	}
	if err := metadata.Validate(); err != nil {
		return relay.BlobMetadata{}, false, fmt.Errorf("stored relay blob failed validation: %v", err)
	}
	return metadata, true, nil
}

func ensureRelayBlobCapacity(
	domain relay.DomainRegistration,
	blobCount int,
	storedByteCount int64,
	byteCount int64,
) error {
	if blobCount >= domain.MaximumBlobCount {
		return relay.NewProtocolError(relay.CodeDomainFull, "domain reached its blob limit")
	}
	if byteCount > domain.MaximumBlobByteCount-storedByteCount {
		return relay.NewProtocolError(
			relay.CodeDomainFull,
			"domain reached its blob-byte limit",
		)
	}
	return nil
}

func insertRelayMember(
	ctx context.Context,
	transaction pgx.Tx,
	registration relay.MemberRegistration,
) error {
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_members (
			tenant_id, domain_id, member_id, version, authorization_digest,
			capabilities, created_at_milliseconds, expires_at_milliseconds,
			revoked_at_milliseconds
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, registration.TenantID, registration.DomainID, registration.MemberID,
		registration.Version, registration.AuthorizationDigest,
		capabilityStrings(registration.Capabilities),
		registration.CreatedAtMilliseconds, registration.ExpiresAtMilliseconds,
		registration.RevokedAtMilliseconds); err != nil {
		return fmt.Errorf("insert relay member: %w", err)
	}
	return nil
}

func insertRelayAudit(
	ctx context.Context,
	transaction pgx.Tx,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	memberID *uuid.UUID,
	messageID *uuid.UUID,
	eventType string,
	nowMilliseconds int64,
) error {
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_audit_events (
			tenant_id, domain_id, member_id, message_id,
			event_type, occurred_at_milliseconds
		) VALUES ($1, $2, $3, $4, $5, $6)
	`, tenantID, domainID, memberID, messageID, eventType, nowMilliseconds); err != nil {
		return fmt.Errorf("insert relay audit event: %w", err)
	}
	return nil
}

func insertRelayAdmissionAudit(
	ctx context.Context,
	transaction pgx.Tx,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	admissionID uuid.UUID,
	memberID *uuid.UUID,
	eventType string,
	nowMilliseconds int64,
) error {
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_audit_events (
			tenant_id, domain_id, admission_id, member_id,
			event_type, occurred_at_milliseconds
		) VALUES ($1, $2, $3, $4, $5, $6)
	`, tenantID, domainID, admissionID, memberID, eventType,
		nowMilliseconds); err != nil {
		return fmt.Errorf("insert relay admission audit event: %w", err)
	}
	return nil
}

func insertRelayBlobAudit(
	ctx context.Context,
	transaction pgx.Tx,
	metadata relay.BlobMetadata,
) error {
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_audit_events (
			tenant_id, domain_id, member_id, blob_id,
			event_type, occurred_at_milliseconds
		) VALUES ($1, $2, $3, $4, 'blob_published', $5)
	`, metadata.TenantID, metadata.DomainID, metadata.PublisherMemberID,
		metadata.BlobID, metadata.CreatedAtMilliseconds); err != nil {
		return fmt.Errorf("insert relay blob audit event: %w", err)
	}
	return nil
}

func capabilityStrings(capabilities []relay.Capability) []string {
	result := make([]string, len(capabilities))
	for index, capability := range capabilities {
		result[index] = string(capability)
	}
	return result
}

func memberEqual(lhs, rhs relay.MemberRegistration) bool {
	if lhs.Version != rhs.Version || lhs.TenantID != rhs.TenantID ||
		lhs.DomainID != rhs.DomainID || lhs.MemberID != rhs.MemberID ||
		lhs.AuthorizationDigest != rhs.AuthorizationDigest ||
		lhs.CreatedAtMilliseconds != rhs.CreatedAtMilliseconds ||
		!optionalInt64Equal(lhs.ExpiresAtMilliseconds, rhs.ExpiresAtMilliseconds) ||
		!optionalInt64Equal(lhs.RevokedAtMilliseconds, rhs.RevokedAtMilliseconds) ||
		len(lhs.Capabilities) != len(rhs.Capabilities) {
		return false
	}
	for index := range lhs.Capabilities {
		if lhs.Capabilities[index] != rhs.Capabilities[index] {
			return false
		}
	}
	return true
}

func admissionCreationEqual(lhs, rhs relay.MemberAdmission) bool {
	if lhs.Version != rhs.Version || lhs.TenantID != rhs.TenantID ||
		lhs.DomainID != rhs.DomainID || lhs.AdmissionID != rhs.AdmissionID ||
		lhs.AuthorizationDigest != rhs.AuthorizationDigest ||
		lhs.ExpiresAtMilliseconds != rhs.ExpiresAtMilliseconds ||
		!optionalInt64Equal(lhs.MemberExpiresAtMilliseconds, rhs.MemberExpiresAtMilliseconds) ||
		len(lhs.Capabilities) != len(rhs.Capabilities) {
		return false
	}
	for index := range lhs.Capabilities {
		if lhs.Capabilities[index] != rhs.Capabilities[index] {
			return false
		}
	}
	return true
}

func optionalInt64Equal(lhs, rhs *int64) bool {
	return lhs == nil && rhs == nil ||
		lhs != nil && rhs != nil && *lhs == *rhs
}
