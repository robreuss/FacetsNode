package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type RelayStore struct {
	pool *pgxpool.Pool
}

func NewRelayStore(pool *pgxpool.Pool) *RelayStore {
	return &RelayStore{pool: pool}
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
	result, err := transaction.Exec(ctx, `
		INSERT INTO relay_domains (
			tenant_id, domain_id, version, administration_digest,
			created_at_milliseconds, maximum_message_count,
			maximum_blob_count, maximum_stored_byte_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, domain_id) DO NOTHING
	`, registration.TenantID, registration.DomainID, registration.Version,
		registration.AdministrationDigest, registration.CreatedAtMilliseconds,
		registration.MaximumMessageCount, registration.MaximumBlobCount,
		registration.MaximumStoredByteCount)
	if err != nil {
		return "", fmt.Errorf("insert relay domain: %w", err)
	}
	if result.RowsAffected() == 0 {
		existing, _, _, _, _, err := loadRelayDomain(
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
	if err := transaction.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit relay domain creation: %w", err)
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
	domain, _, _, _, _, err := loadRelayDomain(
		ctx, transaction, credential.TenantID, credential.DomainID, "FOR SHARE",
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
	result, err := transaction.Exec(ctx, `
		INSERT INTO relay_members (
			tenant_id, domain_id, member_id, version, authorization_digest,
			capabilities, created_at_milliseconds, expires_at_milliseconds,
			revoked_at_milliseconds
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, domain_id, member_id) DO NOTHING
	`, registration.TenantID, registration.DomainID, registration.MemberID,
		registration.Version, registration.AuthorizationDigest,
		capabilityStrings(registration.Capabilities),
		registration.CreatedAtMilliseconds, registration.ExpiresAtMilliseconds,
		registration.RevokedAtMilliseconds)
	if err != nil {
		return "", fmt.Errorf("insert relay member: %w", err)
	}
	if result.RowsAffected() == 0 {
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
		if found && memberEqual(existing, registration) {
			return relay.AcceptanceDuplicate, nil
		}
		return "", relay.NewProtocolError(relay.CodeMemberCollision, "member ID was reused")
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
	domain, _, _, _, _, err := loadRelayDomain(
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
	domain, messageCount, _, storedByteCount, lastSequence, err := loadRelayDomain(
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
	if ciphertextByteCount > domain.MaximumStoredByteCount-storedByteCount {
		return relay.PublishResult{}, relay.NewProtocolError(
			relay.CodeDomainFull,
			"domain reached its stored-byte limit",
		)
	}
	sequence := lastSequence + 1
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_messages (
			tenant_id, domain_id, domain_sequence, message_id,
			publisher_member_id, version, algorithm, key_epoch,
			created_at_milliseconds, nonce, ciphertext, authentication_tag,
			ciphertext_byte_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`, envelope.TenantID, envelope.DomainID, sequence, envelope.MessageID,
		envelope.PublisherMemberID, envelope.Version, envelope.Algorithm,
		int64(envelope.KeyEpoch), envelope.CreatedAtMilliseconds,
		envelope.Nonce, envelope.Ciphertext, envelope.AuthenticationTag,
		ciphertextByteCount); err != nil {
		return relay.PublishResult{}, fmt.Errorf("insert relay message: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE relay_domains
		SET message_count = message_count + 1,
		    stored_byte_count = stored_byte_count + $4,
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
	_, _, _, _, highWatermark, err := loadRelayDomain(
		ctx,
		transaction,
		credential.TenantID,
		credential.DomainID,
		"FOR SHARE",
	)
	if err != nil {
		return relay.FetchResult{}, err
	}
	rows, err := transaction.Query(ctx, `
		SELECT domain_sequence, message_id, publisher_member_id,
		       version, algorithm, key_epoch, created_at_milliseconds,
		       nonce, ciphertext, authentication_tag
		FROM relay_messages
		WHERE tenant_id = $1 AND domain_id = $2
		  AND domain_sequence > $3 AND domain_sequence <= $4
		  AND publisher_member_id <> $5
		ORDER BY domain_sequence
		LIMIT $6
	`, credential.TenantID, credential.DomainID, int64(afterSequence),
		highWatermark, credential.MemberID, limit)
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
	message, found, err := loadRelayMessage(
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
	if message.Envelope.PublisherMemberID == credential.MemberID {
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
		  AND message_id = $3 AND member_id = $4
		FOR UPDATE
	`, credential.TenantID, credential.DomainID, messageID, credential.MemberID).Scan(&existing)
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
				tenant_id, domain_id, message_id, member_id, stage,
				accepted_at_milliseconds
			) VALUES ($1, $2, $3, $4, 'accepted', $5)
			ON CONFLICT (tenant_id, domain_id, message_id, member_id) DO NOTHING
		`, credential.TenantID, credential.DomainID, messageID,
			credential.MemberID, nowMilliseconds)
		if err != nil {
			return relay.AcknowledgmentResult{}, fmt.Errorf("insert relay acknowledgment: %w", err)
		}
		if result.RowsAffected() == 0 {
			if err := transaction.QueryRow(ctx, `
				SELECT stage
				FROM relay_acknowledgments
				WHERE tenant_id = $1 AND domain_id = $2
				  AND message_id = $3 AND member_id = $4
				FOR UPDATE
			`, credential.TenantID, credential.DomainID, messageID,
				credential.MemberID).Scan(&existing); err != nil {
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
			  AND message_id = $3 AND member_id = $4
		`, credential.TenantID, credential.DomainID, messageID,
			credential.MemberID, nowMilliseconds); err != nil {
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
	domain, _, blobCount, storedByteCount, _, err := loadRelayDomain(
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
	return ensureRelayBlobCapacity(domain, blobCount, storedByteCount, byteCount)
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
	domain, _, blobCount, storedByteCount, _, err := loadRelayDomain(
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
	if err := ensureRelayBlobCapacity(
		domain, blobCount, storedByteCount, byteCount,
	); err != nil {
		return relay.BlobPublishResult{}, err
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO relay_blobs (
			tenant_id, domain_id, blob_id, publisher_member_id,
			byte_count, created_at_milliseconds
		) VALUES ($1, $2, $3, $4, $5, $6)
	`, metadata.TenantID, metadata.DomainID, metadata.BlobID,
		metadata.PublisherMemberID, metadata.ByteCount,
		metadata.CreatedAtMilliseconds); err != nil {
		return relay.BlobPublishResult{}, fmt.Errorf("insert relay blob: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE relay_domains
		SET blob_count = blob_count + 1,
		    stored_byte_count = stored_byte_count + $3
		WHERE tenant_id = $1 AND domain_id = $2
	`, credential.TenantID, credential.DomainID, byteCount); err != nil {
		return relay.BlobPublishResult{}, fmt.Errorf("advance relay blob counters: %w", err)
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
	if err := transaction.Commit(ctx); err != nil {
		return relay.BlobMetadata{}, fmt.Errorf("commit relay blob fetch: %w", err)
	}
	return metadata, nil
}

type relayQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadRelayDomain(
	ctx context.Context,
	querier relayQuerier,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	lockClause string,
) (relay.DomainRegistration, int, int, int64, int64, error) {
	query := `
		SELECT version, administration_digest, created_at_milliseconds,
		       maximum_message_count, maximum_blob_count,
		       maximum_stored_byte_count, message_count, blob_count,
		       stored_byte_count, last_sequence
		FROM relay_domains
		WHERE tenant_id = $1 AND domain_id = $2
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	registration := relay.DomainRegistration{TenantID: tenantID, DomainID: domainID}
	var messageCount, blobCount int
	var storedByteCount, lastSequence int64
	err := querier.QueryRow(ctx, query, tenantID, domainID).Scan(
		&registration.Version,
		&registration.AdministrationDigest,
		&registration.CreatedAtMilliseconds,
		&registration.MaximumMessageCount,
		&registration.MaximumBlobCount,
		&registration.MaximumStoredByteCount,
		&messageCount,
		&blobCount,
		&storedByteCount,
		&lastSequence,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return relay.DomainRegistration{}, 0, 0, 0, 0, relay.NewProtocolError(
			relay.CodeDomainNotFound,
			"domain was not found",
		)
	}
	if err != nil {
		return relay.DomainRegistration{}, 0, 0, 0, 0, fmt.Errorf("load relay domain: %w", err)
	}
	if err := registration.Validate(); err != nil {
		return relay.DomainRegistration{}, 0, 0, 0, 0, fmt.Errorf("stored relay domain failed validation: %v", err)
	}
	if messageCount < 0 || messageCount > registration.MaximumMessageCount ||
		blobCount < 0 || blobCount > registration.MaximumBlobCount ||
		storedByteCount < 0 || storedByteCount > registration.MaximumStoredByteCount ||
		lastSequence < int64(messageCount) {
		return relay.DomainRegistration{}, 0, 0, 0, 0, fmt.Errorf("stored relay domain counters are invalid")
	}
	return registration, messageCount, blobCount, storedByteCount, lastSequence, nil
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
	if byteCount > domain.MaximumStoredByteCount-storedByteCount {
		return relay.NewProtocolError(
			relay.CodeDomainFull,
			"domain reached its stored-byte limit",
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

func optionalInt64Equal(lhs, rhs *int64) bool {
	return lhs == nil && rhs == nil ||
		lhs != nil && rhs != nil && *lhs == *rhs
}
