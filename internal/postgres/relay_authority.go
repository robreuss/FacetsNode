package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/relay"
)

const (
	administrationRotationSubject = "administration"
	memberRotationSubject         = "member"
)

type storedCredentialRotation struct {
	rotationID                  uuid.UUID
	subjectType                 string
	subjectID                   uuid.UUID
	previousAuthorizationDigest string
	newAuthorizationDigest      string
	rotatedAtMilliseconds       int64
}

func (s *RelayStore) RotateAdministrationCredential(
	ctx context.Context,
	credential relay.AdministrationCredential,
	rotation relay.CredentialRotation,
	nowMilliseconds int64,
) (relay.CredentialRotationResult, error) {
	if err := rotation.Validate(); err != nil {
		return relay.CredentialRotationResult{}, err
	}
	actualDigest, err := relay.AdministrationDigest(credential)
	if err != nil {
		return relay.CredentialRotationResult{}, relay.NewProtocolError(
			relay.CodeUnauthorized,
			"administration credential is invalid",
		)
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.CredentialRotationResult{}, fmt.Errorf(
			"begin administration credential rotation: %w",
			err,
		)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	domain, _, _, _, _, _, err := loadRelayDomain(
		ctx, transaction, credential.TenantID, credential.DomainID, "FOR UPDATE",
	)
	if err != nil {
		return relay.CredentialRotationResult{}, err
	}
	existing, found, err := loadRelayCredentialRotation(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		rotation.RotationID,
		"FOR UPDATE",
	)
	if err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if found {
		return postgresRotationRetryResult(
			existing,
			administrationRotationSubject,
			credential.DomainID,
			actualDigest,
			rotation,
		)
	}
	if err := domain.Authorize(credential); err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if nowMilliseconds < domain.CreatedAtMilliseconds {
		return relay.CredentialRotationResult{}, relay.NewProtocolError(
			relay.CodeInvalidCredentialRotation,
			"credential rotation precedes domain creation",
		)
	}
	if rotation.AuthorizationDigest == domain.AdministrationDigest {
		return relay.CredentialRotationResult{}, relay.NewProtocolError(
			relay.CodeCredentialReuse,
			"administration credential digest was already used",
		)
	}
	used, err := relayCredentialDigestWasUsed(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		administrationRotationSubject,
		credential.DomainID,
		rotation.AuthorizationDigest,
	)
	if err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if used {
		return relay.CredentialRotationResult{}, relay.NewProtocolError(
			relay.CodeCredentialReuse,
			"administration credential digest was already used",
		)
	}
	if err := ensurePostgresCredentialRotationCapacity(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		administrationRotationSubject,
		credential.DomainID,
	); err != nil {
		return relay.CredentialRotationResult{}, err
	}
	record := storedCredentialRotation{
		rotationID:                  rotation.RotationID,
		subjectType:                 administrationRotationSubject,
		subjectID:                   credential.DomainID,
		previousAuthorizationDigest: domain.AdministrationDigest,
		newAuthorizationDigest:      rotation.AuthorizationDigest,
		rotatedAtMilliseconds:       nowMilliseconds,
	}
	if err := insertRelayCredentialRotation(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		record,
	); err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE relay_domains
		SET administration_digest = $3
		WHERE tenant_id = $1 AND domain_id = $2
	`, credential.TenantID, credential.DomainID,
		rotation.AuthorizationDigest); err != nil {
		return relay.CredentialRotationResult{}, fmt.Errorf(
			"update relay administration credential: %w",
			err,
		)
	}
	if err := insertRelayRotationAudit(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		rotation.RotationID,
		nil,
		"administration_credential_rotated",
		nowMilliseconds,
	); err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return relay.CredentialRotationResult{}, fmt.Errorf(
			"commit administration credential rotation: %w",
			err,
		)
	}
	return relay.CredentialRotationResult{
		Acceptance:            relay.AcceptanceAccepted,
		RotationID:            rotation.RotationID,
		AuthorizationDigest:   rotation.AuthorizationDigest,
		RotatedAtMilliseconds: nowMilliseconds,
	}, nil
}

func (s *RelayStore) RotateMemberCredential(
	ctx context.Context,
	credential relay.Credential,
	rotation relay.CredentialRotation,
	nowMilliseconds int64,
) (relay.CredentialRotationResult, error) {
	if err := rotation.Validate(); err != nil {
		return relay.CredentialRotationResult{}, err
	}
	actualDigest, err := relay.AuthorizationDigest(credential)
	if err != nil {
		return relay.CredentialRotationResult{}, relay.NewProtocolError(
			relay.CodeUnauthorized,
			"member credential is invalid",
		)
	}
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.CredentialRotationResult{}, fmt.Errorf(
			"begin member credential rotation: %w",
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
		return relay.CredentialRotationResult{}, err
	}
	member, found, err := loadRelayMember(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		credential.MemberID,
		"FOR UPDATE",
	)
	if err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if !found {
		return relay.CredentialRotationResult{}, relay.NewProtocolError(
			relay.CodeMemberNotFound,
			"member was not found",
		)
	}
	existing, rotationFound, err := loadRelayCredentialRotation(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		rotation.RotationID,
		"FOR UPDATE",
	)
	if err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if rotationFound {
		return postgresRotationRetryResult(
			existing,
			memberRotationSubject,
			credential.MemberID,
			actualDigest,
			rotation,
		)
	}
	if err := member.VerifyCredential(credential, nowMilliseconds); err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if rotation.AuthorizationDigest == member.AuthorizationDigest {
		return relay.CredentialRotationResult{}, relay.NewProtocolError(
			relay.CodeCredentialReuse,
			"member credential digest was already used",
		)
	}
	used, err := relayCredentialDigestWasUsed(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		memberRotationSubject,
		credential.MemberID,
		rotation.AuthorizationDigest,
	)
	if err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if used {
		return relay.CredentialRotationResult{}, relay.NewProtocolError(
			relay.CodeCredentialReuse,
			"member credential digest was already used",
		)
	}
	if err := ensurePostgresCredentialRotationCapacity(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		memberRotationSubject,
		credential.MemberID,
	); err != nil {
		return relay.CredentialRotationResult{}, err
	}
	record := storedCredentialRotation{
		rotationID:                  rotation.RotationID,
		subjectType:                 memberRotationSubject,
		subjectID:                   credential.MemberID,
		previousAuthorizationDigest: member.AuthorizationDigest,
		newAuthorizationDigest:      rotation.AuthorizationDigest,
		rotatedAtMilliseconds:       nowMilliseconds,
	}
	if err := insertRelayCredentialRotation(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		record,
	); err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE relay_members
		SET authorization_digest = $4, updated_at = now()
		WHERE tenant_id = $1 AND domain_id = $2 AND member_id = $3
	`, credential.TenantID, credential.DomainID, credential.MemberID,
		rotation.AuthorizationDigest); err != nil {
		return relay.CredentialRotationResult{}, fmt.Errorf(
			"update relay member credential: %w",
			err,
		)
	}
	if err := insertRelayRotationAudit(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		rotation.RotationID,
		&credential.MemberID,
		"member_credential_rotated",
		nowMilliseconds,
	); err != nil {
		return relay.CredentialRotationResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return relay.CredentialRotationResult{}, fmt.Errorf(
			"commit member credential rotation: %w",
			err,
		)
	}
	return relay.CredentialRotationResult{
		Acceptance:            relay.AcceptanceAccepted,
		RotationID:            rotation.RotationID,
		AuthorizationDigest:   rotation.AuthorizationDigest,
		RotatedAtMilliseconds: nowMilliseconds,
	}, nil
}

func (s *RelayStore) CollectAdmissions(
	ctx context.Context,
	credential relay.AdministrationCredential,
	nowMilliseconds int64,
) (relay.AdmissionCollectionResult, error) {
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.AdmissionCollectionResult{}, fmt.Errorf(
			"begin relay admission collection: %w",
			err,
		)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	domain, _, _, _, _, _, err := loadRelayDomain(
		ctx, transaction, credential.TenantID, credential.DomainID, "FOR UPDATE",
	)
	if err != nil {
		return relay.AdmissionCollectionResult{}, err
	}
	if err := domain.Authorize(credential); err != nil {
		return relay.AdmissionCollectionResult{}, err
	}
	cutoff := int64(0)
	admissionIDs := make([]uuid.UUID, 0, relay.MaximumAdmissionCollectionBatch+1)
	if nowMilliseconds > relay.AdmissionRecoveryWindowMilliseconds {
		cutoff = nowMilliseconds - relay.AdmissionRecoveryWindowMilliseconds
		rows, err := transaction.Query(ctx, `
		SELECT admission_id
		FROM relay_member_admissions
		WHERE tenant_id = $1 AND domain_id = $2
		  AND COALESCE(
		      claimed_at_milliseconds,
		      revoked_at_milliseconds,
		      expires_at_milliseconds
		  ) <= $3
		ORDER BY COALESCE(
		    claimed_at_milliseconds,
		    revoked_at_milliseconds,
		    expires_at_milliseconds
		), admission_id
		LIMIT $4
		FOR UPDATE
		`, credential.TenantID, credential.DomainID, cutoff,
			relay.MaximumAdmissionCollectionBatch+1)
		if err != nil {
			return relay.AdmissionCollectionResult{}, fmt.Errorf(
				"select collectible relay admissions: %w",
				err,
			)
		}
		for rows.Next() {
			var admissionID uuid.UUID
			if err := rows.Scan(&admissionID); err != nil {
				rows.Close()
				return relay.AdmissionCollectionResult{}, fmt.Errorf(
					"scan collectible relay admission: %w",
					err,
				)
			}
			admissionIDs = append(admissionIDs, admissionID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return relay.AdmissionCollectionResult{}, fmt.Errorf(
				"iterate collectible relay admissions: %w",
				err,
			)
		}
		rows.Close()
	}
	hasMore := len(admissionIDs) > relay.MaximumAdmissionCollectionBatch
	if hasMore {
		admissionIDs = admissionIDs[:relay.MaximumAdmissionCollectionBatch]
	}
	for _, admissionID := range admissionIDs {
		if err := insertRelayAdmissionAudit(
			ctx,
			transaction,
			credential.TenantID,
			credential.DomainID,
			admissionID,
			nil,
			"admission_collected",
			nowMilliseconds,
		); err != nil {
			return relay.AdmissionCollectionResult{}, err
		}
		if _, err := transaction.Exec(ctx, `
			DELETE FROM relay_member_admissions
			WHERE tenant_id = $1 AND domain_id = $2 AND admission_id = $3
		`, credential.TenantID, credential.DomainID, admissionID); err != nil {
			return relay.AdmissionCollectionResult{}, fmt.Errorf(
				"delete collected relay admission: %w",
				err,
			)
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return relay.AdmissionCollectionResult{}, fmt.Errorf(
			"commit relay admission collection: %w",
			err,
		)
	}
	return relay.AdmissionCollectionResult{
		CollectedCount:             len(admissionIDs),
		HasMore:                    hasMore,
		EligibleBeforeMilliseconds: cutoff,
	}, nil
}

func ensurePostgresMemberCapacity(
	ctx context.Context,
	transaction pgx.Tx,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	nowMilliseconds int64,
) error {
	var retainedCount, activeCount int
	if err := transaction.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (
		    WHERE created_at_milliseconds <= $3
		      AND (revoked_at_milliseconds IS NULL OR revoked_at_milliseconds > $3)
		      AND (expires_at_milliseconds IS NULL OR expires_at_milliseconds > $3)
		)
		FROM relay_members
		WHERE tenant_id = $1 AND domain_id = $2
	`, tenantID, domainID, nowMilliseconds).Scan(
		&retainedCount,
		&activeCount,
	); err != nil {
		return fmt.Errorf("count relay members: %w", err)
	}
	if retainedCount >= relay.MaximumRetainedMemberCountPerDomain {
		return relay.NewProtocolError(
			relay.CodeDomainFull,
			"domain reached its retained member limit",
		)
	}
	if activeCount >= relay.MaximumActiveMemberCountPerDomain {
		return relay.NewProtocolError(
			relay.CodeDomainFull,
			"domain reached its active member limit",
		)
	}
	return nil
}

func ensurePostgresAdmissionCapacity(
	ctx context.Context,
	transaction pgx.Tx,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	nowMilliseconds int64,
) error {
	var retainedCount, outstandingCount int
	if err := transaction.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (
		    WHERE created_at_milliseconds <= $3
		      AND claimed_at_milliseconds IS NULL
		      AND (revoked_at_milliseconds IS NULL OR revoked_at_milliseconds > $3)
		      AND expires_at_milliseconds > $3
		)
		FROM relay_member_admissions
		WHERE tenant_id = $1 AND domain_id = $2
	`, tenantID, domainID, nowMilliseconds).Scan(
		&retainedCount,
		&outstandingCount,
	); err != nil {
		return fmt.Errorf("count relay admissions: %w", err)
	}
	if retainedCount >= relay.MaximumRetainedAdmissionCount {
		return relay.NewProtocolError(
			relay.CodeDomainFull,
			"domain reached its retained admission limit",
		)
	}
	if outstandingCount >= relay.MaximumOutstandingAdmissionCount {
		return relay.NewProtocolError(
			relay.CodeDomainFull,
			"domain reached its outstanding admission limit",
		)
	}
	return nil
}

func ensurePostgresCredentialRotationCapacity(
	ctx context.Context,
	transaction pgx.Tx,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
) error {
	var domainCount, subjectCount int
	if err := transaction.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (
		    WHERE subject_type = $3 AND subject_id = $4
		)
		FROM relay_credential_rotations
		WHERE tenant_id = $1 AND domain_id = $2
	`, tenantID, domainID, subjectType, subjectID).Scan(
		&domainCount,
		&subjectCount,
	); err != nil {
		return fmt.Errorf("count relay credential rotations: %w", err)
	}
	if domainCount >= relay.MaximumCredentialRotationsPerDomain {
		return relay.NewProtocolError(
			relay.CodeDomainFull,
			"domain reached its credential rotation limit",
		)
	}
	if subjectCount >= relay.MaximumCredentialRotationsPerSubject {
		return relay.NewProtocolError(
			relay.CodeDomainFull,
			"subject reached its credential rotation limit",
		)
	}
	return nil
}

func loadRelayCredentialRotation(
	ctx context.Context,
	querier relayQuerier,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	rotationID uuid.UUID,
	lockClause string,
) (storedCredentialRotation, bool, error) {
	query := `
		SELECT subject_type, subject_id, previous_authorization_digest,
		       new_authorization_digest, rotated_at_milliseconds
		FROM relay_credential_rotations
		WHERE tenant_id = $1 AND domain_id = $2 AND rotation_id = $3
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	record := storedCredentialRotation{rotationID: rotationID}
	err := querier.QueryRow(ctx, query, tenantID, domainID, rotationID).Scan(
		&record.subjectType,
		&record.subjectID,
		&record.previousAuthorizationDigest,
		&record.newAuthorizationDigest,
		&record.rotatedAtMilliseconds,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedCredentialRotation{}, false, nil
	}
	if err != nil {
		return storedCredentialRotation{}, false, fmt.Errorf(
			"load relay credential rotation: %w",
			err,
		)
	}
	return record, true, nil
}

func postgresRotationRetryResult(
	existing storedCredentialRotation,
	subjectType string,
	subjectID uuid.UUID,
	actualDigest string,
	rotation relay.CredentialRotation,
) (relay.CredentialRotationResult, error) {
	if actualDigest != existing.previousAuthorizationDigest &&
		actualDigest != existing.newAuthorizationDigest {
		return relay.CredentialRotationResult{}, relay.NewProtocolError(
			relay.CodeUnauthorized,
			"credential is not authorized for this rotation",
		)
	}
	if existing.subjectType != subjectType || existing.subjectID != subjectID ||
		existing.newAuthorizationDigest != rotation.AuthorizationDigest {
		return relay.CredentialRotationResult{}, relay.NewProtocolError(
			relay.CodeCredentialRotationCollision,
			"credential rotation ID was reused",
		)
	}
	return relay.CredentialRotationResult{
		Acceptance:            relay.AcceptanceDuplicate,
		RotationID:            rotation.RotationID,
		AuthorizationDigest:   existing.newAuthorizationDigest,
		RotatedAtMilliseconds: existing.rotatedAtMilliseconds,
	}, nil
}

func relayCredentialDigestWasUsed(
	ctx context.Context,
	querier relayQuerier,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
	digest string,
) (bool, error) {
	var used bool
	if err := querier.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM relay_credential_rotations
		    WHERE tenant_id = $1 AND domain_id = $2
		      AND subject_type = $3 AND subject_id = $4
		      AND ($5 = previous_authorization_digest OR $5 = new_authorization_digest)
		)
	`, tenantID, domainID, subjectType, subjectID, digest).Scan(&used); err != nil {
		return false, fmt.Errorf("check relay credential digest history: %w", err)
	}
	return used, nil
}

func insertRelayCredentialRotation(
	ctx context.Context,
	transaction pgx.Tx,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	record storedCredentialRotation,
) error {
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_credential_rotations (
			tenant_id, domain_id, rotation_id, subject_type, subject_id,
			previous_authorization_digest, new_authorization_digest,
			rotated_at_milliseconds
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, tenantID, domainID, record.rotationID,
		record.subjectType, record.subjectID,
		record.previousAuthorizationDigest, record.newAuthorizationDigest,
		record.rotatedAtMilliseconds); err != nil {
		return fmt.Errorf("insert relay credential rotation: %w", err)
	}
	return nil
}

func insertRelayRotationAudit(
	ctx context.Context,
	transaction pgx.Tx,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	rotationID uuid.UUID,
	memberID *uuid.UUID,
	eventType string,
	nowMilliseconds int64,
) error {
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_audit_events (
			tenant_id, domain_id, credential_rotation_id, member_id,
			event_type, occurred_at_milliseconds
		) VALUES ($1, $2, $3, $4, $5, $6)
	`, tenantID, domainID, rotationID, memberID, eventType,
		nowMilliseconds); err != nil {
		return fmt.Errorf("insert relay credential rotation audit event: %w", err)
	}
	return nil
}
