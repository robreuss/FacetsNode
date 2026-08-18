package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type storedBlobUpload struct {
	status            relay.BlobUploadStatus
	createRetryID     uuid.UUID
	subscriptionID    uuid.UUID
	publisherMemberID uuid.UUID
	state             string
}

func (s *RelayStore) CreateBlobUpload(
	ctx context.Context, credential relay.Credential, request relay.BlobUploadRequest, nowMilliseconds int64,
) (relay.BlobUploadCreateResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	if request.CreatedAtMilliseconds > nowMilliseconds {
		return relay.BlobUploadCreateResponse{}, relay.NewProtocolError(relay.CodeInvalidBlobUpload, "blob upload creation is in the future")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenant, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE")
	if err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	domain, _, _, blobCount, blobBytes, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE")
	if err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	subscriptionID, err := authorizeBlobUploadMember(ctx, tx, credential, nowMilliseconds)
	if err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	if existing, found, err := loadBlobUploadByRetry(ctx, tx, credential.TenantID, credential.DomainID, request.RetryID, "FOR UPDATE"); err != nil {
		return relay.BlobUploadCreateResponse{}, err
	} else if found {
		if existing.state == "expired" {
			return relay.BlobUploadCreateResponse{}, relay.NewProtocolError(relay.CodeBlobUploadNotFound, "blob upload expired")
		}
		if existing.status.UploadID == request.UploadID && existing.status.RelayBlobID == request.RelayBlobID &&
			existing.status.ByteCount == request.ByteCount && existing.status.CreatedAtMilliseconds == request.CreatedAtMilliseconds &&
			existing.subscriptionID == subscriptionID {
			return relay.BlobUploadCreateResponse{Acceptance: relay.AcceptanceDuplicate, RetryID: request.RetryID, Status: existing.status}, nil
		}
		return relay.BlobUploadCreateResponse{}, relay.NewProtocolError(relay.CodeBlobUploadCollision, "blob upload retry ID was reused")
	}
	if err := postgresFenceAllowsWrite(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, nowMilliseconds); err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	if _, found, err := loadBlobUpload(ctx, tx, credential.TenantID, credential.DomainID, request.UploadID, "FOR UPDATE"); err != nil {
		return relay.BlobUploadCreateResponse{}, err
	} else if found {
		return relay.BlobUploadCreateResponse{}, relay.NewProtocolError(relay.CodeBlobUploadCollision, "blob upload ID was reused")
	}
	if existing, found, err := loadRelayBlob(ctx, tx, credential.TenantID, credential.DomainID, request.RelayBlobID, "FOR SHARE"); err != nil {
		return relay.BlobUploadCreateResponse{}, err
	} else if found {
		if existing.ByteCount != request.ByteCount {
			return relay.BlobUploadCreateResponse{}, relay.NewProtocolError(relay.CodeBlobCollision, "blob ID was reused with a different length")
		}
		return relay.BlobUploadCreateResponse{}, relay.NewProtocolError(relay.CodeBlobUploadCollision, "blob is already published")
	}
	var domainReservedCount int
	var domainReservedBytes int64
	if err := tx.QueryRow(ctx, `SELECT reserved_blob_count,reserved_blob_byte_count FROM relay_domains WHERE tenant_id=$1 AND domain_id=$2`, credential.TenantID, credential.DomainID).Scan(&domainReservedCount, &domainReservedBytes); err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	if blobCount+domainReservedCount >= domain.MaximumBlobCount || request.ByteCount > domain.MaximumBlobByteCount-blobBytes-domainReservedBytes {
		return relay.BlobUploadCreateResponse{}, relay.NewProtocolError(relay.CodeDomainFull, "domain reached its blob quota")
	}
	var tenantBlobCount, tenantReservedCount int
	var tenantBlobBytes, tenantReservedBytes int64
	if err := tx.QueryRow(ctx, `SELECT blob_count,aggregate_blob_byte_count,reserved_blob_count,reserved_blob_byte_count FROM relay_tenants WHERE tenant_id=$1`, credential.TenantID).Scan(&tenantBlobCount, &tenantBlobBytes, &tenantReservedCount, &tenantReservedBytes); err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	if tenantBlobCount+tenantReservedCount >= tenant.MaximumAggregateBlobCount || request.ByteCount > tenant.MaximumAggregateBlobByteCount-tenantBlobBytes-tenantReservedBytes {
		return relay.BlobUploadCreateResponse{}, relay.NewProtocolError(relay.CodeTenantFull, "tenant reached its aggregate blob quota")
	}
	expires := nowMilliseconds + s.blobUploadTTL.Milliseconds()
	if expires < nowMilliseconds {
		return relay.BlobUploadCreateResponse{}, fmt.Errorf("blob upload expiry overflow")
	}
	_, err = tx.Exec(ctx, `INSERT INTO relay_blob_uploads (tenant_id,domain_id,upload_id,create_retry_id,subscription_id,publisher_member_id,relay_blob_id,byte_count,created_at_milliseconds,updated_at_milliseconds,expires_at_milliseconds) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10)`, credential.TenantID, credential.DomainID, request.UploadID, request.RetryID, subscriptionID, credential.MemberID, request.RelayBlobID, request.ByteCount, request.CreatedAtMilliseconds, expires)
	if err != nil {
		return relay.BlobUploadCreateResponse{}, fmt.Errorf("insert blob upload: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_domains SET reserved_blob_count=reserved_blob_count+1,reserved_blob_byte_count=reserved_blob_byte_count+$3 WHERE tenant_id=$1 AND domain_id=$2`, credential.TenantID, credential.DomainID, request.ByteCount); err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_tenants SET reserved_blob_count=reserved_blob_count+1,reserved_blob_byte_count=reserved_blob_byte_count+$2 WHERE tenant_id=$1`, credential.TenantID, request.ByteCount); err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.BlobUploadCreateResponse{}, err
	}
	status := relay.BlobUploadStatus{UploadID: request.UploadID, RelayBlobID: request.RelayBlobID, ByteCount: request.ByteCount, CreatedAtMilliseconds: request.CreatedAtMilliseconds, UpdatedAtMilliseconds: request.CreatedAtMilliseconds}
	return relay.BlobUploadCreateResponse{Acceptance: relay.AcceptanceAccepted, RetryID: request.RetryID, Status: status}, nil
}

func (s *RelayStore) GetBlobUpload(ctx context.Context, credential relay.Credential, uploadID uuid.UUID, nowMilliseconds int64) (relay.BlobUploadStatus, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.BlobUploadStatus{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	subscriptionID, err := authorizeBlobUploadMember(ctx, tx, credential, nowMilliseconds)
	if err != nil {
		return relay.BlobUploadStatus{}, err
	}
	upload, found, err := loadBlobUpload(ctx, tx, credential.TenantID, credential.DomainID, uploadID, "FOR SHARE")
	if err != nil {
		return relay.BlobUploadStatus{}, err
	}
	if !found || upload.state == "expired" {
		return relay.BlobUploadStatus{}, relay.NewProtocolError(relay.CodeBlobUploadNotFound, "blob upload was not found")
	}
	if upload.subscriptionID != subscriptionID {
		return relay.BlobUploadStatus{}, relay.NewProtocolError(relay.CodeWrongScope, "blob upload belongs to another subscription")
	}
	return upload.status, nil
}

func (s *RelayStore) AppendBlobUploadChunk(
	ctx context.Context,
	credential relay.Credential,
	request relay.BlobUploadChunkRequest,
	nowMilliseconds int64,
	write func(relay.BlobUploadStatus) error,
) (relay.BlobUploadStatus, error) {
	if err := request.Validate(); err != nil {
		return relay.BlobUploadStatus{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.BlobUploadStatus{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE"); err != nil {
		return relay.BlobUploadStatus{}, err
	}
	if _, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE"); err != nil {
		return relay.BlobUploadStatus{}, err
	}
	subscriptionID, err := authorizeBlobUploadMember(ctx, tx, credential, nowMilliseconds)
	if err != nil {
		return relay.BlobUploadStatus{}, err
	}
	upload, found, err := loadBlobUpload(ctx, tx, credential.TenantID, credential.DomainID, request.UploadID, "FOR UPDATE")
	if err != nil {
		return relay.BlobUploadStatus{}, err
	}
	if !found || upload.state == "expired" {
		return relay.BlobUploadStatus{}, relay.NewProtocolError(relay.CodeBlobUploadNotFound, "blob upload was not found")
	}
	if upload.subscriptionID != subscriptionID {
		return relay.BlobUploadStatus{}, relay.NewProtocolError(relay.CodeWrongScope, "blob upload belongs to another subscription")
	}
	var byteCount int64
	var digest string
	err = tx.QueryRow(ctx, `SELECT byte_count,chunk_sha256 FROM relay_blob_upload_chunks WHERE tenant_id=$1 AND domain_id=$2 AND upload_id=$3 AND chunk_offset=$4`, credential.TenantID, credential.DomainID, request.UploadID, request.Offset).Scan(&byteCount, &digest)
	if err == nil {
		if byteCount == request.ByteCount && digest == request.ChunkSHA256 {
			return upload.status, nil
		}
		return relay.BlobUploadStatus{}, relay.NewProtocolError(relay.CodeBlobUploadCollision, "blob upload chunk offset was reused")
	}
	if err != pgx.ErrNoRows {
		return relay.BlobUploadStatus{}, err
	}
	if err := postgresFenceAllowsWrite(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, nowMilliseconds); err != nil {
		return relay.BlobUploadStatus{}, err
	}
	if upload.state != "active" || request.Offset != upload.status.CommittedOffset || request.ByteCount > upload.status.ByteCount-request.Offset {
		return relay.BlobUploadStatus{}, relay.NewProtocolError(relay.CodeInvalidBlobUpload, "blob upload chunk is not contiguous")
	}
	if write == nil {
		return relay.BlobUploadStatus{}, relay.NewProtocolError(relay.CodeInvalidBlobUpload, "blob upload writer is missing")
	}
	// Keep the upload row locked across tail repair, append, and fsync. A second
	// instance cannot inspect a stale offset or touch staging until this exact
	// chunk and the durable offset commit together.
	if err := write(upload.status); err != nil {
		return relay.BlobUploadStatus{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_blob_upload_chunks (tenant_id,domain_id,upload_id,chunk_offset,byte_count,chunk_sha256,committed_at_milliseconds) VALUES ($1,$2,$3,$4,$5,$6,$7)`, credential.TenantID, credential.DomainID, request.UploadID, request.Offset, request.ByteCount, request.ChunkSHA256, nowMilliseconds); err != nil {
		return relay.BlobUploadStatus{}, err
	}
	upload.status.CommittedOffset += request.ByteCount
	upload.status.UpdatedAtMilliseconds = nowMilliseconds
	expires := nowMilliseconds + s.blobUploadTTL.Milliseconds()
	if _, err := tx.Exec(ctx, `UPDATE relay_blob_uploads SET committed_offset=$4,updated_at_milliseconds=$5,expires_at_milliseconds=$6,updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND upload_id=$3`, credential.TenantID, credential.DomainID, request.UploadID, upload.status.CommittedOffset, nowMilliseconds, expires); err != nil {
		return relay.BlobUploadStatus{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.BlobUploadStatus{}, err
	}
	return upload.status, nil
}

func (s *RelayStore) FinalizeBlobUpload(
	ctx context.Context,
	credential relay.Credential,
	request relay.BlobUploadFinalizationRequest,
	nowMilliseconds int64,
	publish func(relay.BlobUploadStatus) error,
) (relay.BlobUploadFinalizationResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE"); err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	if _, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE"); err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	subscriptionID, err := authorizeBlobUploadMember(ctx, tx, credential, nowMilliseconds)
	if err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	var oldUpload uuid.UUID
	var oldBlob string
	var oldBytes, oldFinalized int64
	err = tx.QueryRow(ctx, `SELECT upload_id,relay_blob_id,byte_count,finalized_at_milliseconds FROM relay_blob_upload_finalizations WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3`, credential.TenantID, credential.DomainID, request.RetryID).Scan(&oldUpload, &oldBlob, &oldBytes, &oldFinalized)
	if err == nil {
		if oldUpload == request.UploadID && oldBlob == request.RelayBlobID && oldBytes == request.ByteCount && oldFinalized == request.FinalizedAtMilliseconds {
			return relay.BlobUploadFinalizationResponse{Acceptance: relay.AcceptanceDuplicate, RetryID: request.RetryID, UploadID: request.UploadID, RelayBlobID: request.RelayBlobID, ByteCount: request.ByteCount}, nil
		}
		return relay.BlobUploadFinalizationResponse{}, relay.NewProtocolError(relay.CodeBlobUploadCollision, "blob upload finalization retry ID was reused")
	}
	if err != pgx.ErrNoRows {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	upload, found, err := loadBlobUpload(ctx, tx, credential.TenantID, credential.DomainID, request.UploadID, "FOR UPDATE")
	if err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	if !found || upload.state == "expired" {
		return relay.BlobUploadFinalizationResponse{}, relay.NewProtocolError(relay.CodeBlobUploadNotFound, "blob upload was not found")
	}
	if upload.subscriptionID != subscriptionID {
		return relay.BlobUploadFinalizationResponse{}, relay.NewProtocolError(relay.CodeWrongScope, "blob upload belongs to another subscription")
	}
	if err := postgresFenceAllowsWrite(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, nowMilliseconds); err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	fenceID, err := postgresActiveFenceForSubscription(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID)
	if err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	if upload.state != "active" || request.RelayBlobID != upload.status.RelayBlobID || request.ByteCount != upload.status.ByteCount || upload.status.CommittedOffset != upload.status.ByteCount {
		return relay.BlobUploadFinalizationResponse{}, relay.NewProtocolError(relay.CodeInvalidBlobUpload, "blob upload finalization does not match staged content")
	}
	existing, blobFound, err := loadRelayBlob(ctx, tx, credential.TenantID, credential.DomainID, request.RelayBlobID, "FOR UPDATE")
	if err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	if blobFound && existing.ByteCount != request.ByteCount {
		return relay.BlobUploadFinalizationResponse{}, relay.NewProtocolError(relay.CodeBlobCollision, "blob ID was reused with a different length")
	}
	if !blobFound {
		if publish == nil {
			return relay.BlobUploadFinalizationResponse{}, relay.NewProtocolError(relay.CodeInvalidBlobUpload, "blob upload publisher is missing")
		}
		// Keep tenant, domain, and upload locked across atomic filesystem
		// publication so orphan reconciliation cannot delete a same-ID file
		// between its authority check and this metadata commit.
		if err := publish(upload.status); err != nil {
			return relay.BlobUploadFinalizationResponse{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO relay_blobs (tenant_id,domain_id,blob_id,publisher_member_id,byte_count,created_at_milliseconds,checkpoint_fence_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`, credential.TenantID, credential.DomainID, request.RelayBlobID, upload.publisherMemberID, request.ByteCount, nowMilliseconds, fenceID); err != nil {
			return relay.BlobUploadFinalizationResponse{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE relay_domains SET blob_count=blob_count+1,blob_byte_count=blob_byte_count+$3,reserved_blob_count=reserved_blob_count-1,reserved_blob_byte_count=reserved_blob_byte_count-$3 WHERE tenant_id=$1 AND domain_id=$2`, credential.TenantID, credential.DomainID, request.ByteCount); err != nil {
			return relay.BlobUploadFinalizationResponse{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE relay_tenants SET blob_count=blob_count+1,aggregate_blob_byte_count=aggregate_blob_byte_count+$2,reserved_blob_count=reserved_blob_count-1,reserved_blob_byte_count=reserved_blob_byte_count-$2 WHERE tenant_id=$1`, credential.TenantID, request.ByteCount); err != nil {
			return relay.BlobUploadFinalizationResponse{}, err
		}
	} else {
		if _, err := tx.Exec(ctx, `UPDATE relay_domains SET reserved_blob_count=reserved_blob_count-1,reserved_blob_byte_count=reserved_blob_byte_count-$3 WHERE tenant_id=$1 AND domain_id=$2`, credential.TenantID, credential.DomainID, request.ByteCount); err != nil {
			return relay.BlobUploadFinalizationResponse{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE relay_tenants SET reserved_blob_count=reserved_blob_count-1,reserved_blob_byte_count=reserved_blob_byte_count-$2 WHERE tenant_id=$1`, credential.TenantID, request.ByteCount); err != nil {
			return relay.BlobUploadFinalizationResponse{}, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_blob_uploads SET state='finalized',finalized_at_milliseconds=$4,updated_at_milliseconds=$4,updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND upload_id=$3`, credential.TenantID, credential.DomainID, request.UploadID, nowMilliseconds); err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_blob_upload_finalizations VALUES ($1,$2,$3,$4,$5,$6,$7,now())`, credential.TenantID, credential.DomainID, request.RetryID, request.UploadID, request.RelayBlobID, request.ByteCount, request.FinalizedAtMilliseconds); err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_blob_upload_deletions VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, credential.TenantID, credential.DomainID, request.UploadID, request.FinalizedAtMilliseconds); err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.BlobUploadFinalizationResponse{}, err
	}
	return relay.BlobUploadFinalizationResponse{Acceptance: relay.AcceptanceAccepted, RetryID: request.RetryID, UploadID: request.UploadID, RelayBlobID: request.RelayBlobID, ByteCount: request.ByteCount}, nil
}

func authorizeBlobUploadMember(ctx context.Context, q relayQuerier, credential relay.Credential, nowMilliseconds int64) (uuid.UUID, error) {
	member, found, err := loadRelayMember(ctx, q, credential.TenantID, credential.DomainID, credential.MemberID, "FOR SHARE")
	if err != nil {
		return uuid.Nil, err
	}
	if !found {
		return uuid.Nil, relay.NewProtocolError(relay.CodeMemberNotFound, "member was not found")
	}
	if err := member.Authorize(credential, relay.CapabilityPublishBlob, nowMilliseconds); err != nil {
		return uuid.Nil, err
	}
	return loadActiveMemberSubscription(ctx, q, credential.TenantID, credential.DomainID, credential.MemberID, "FOR SHARE")
}

func loadBlobUpload(ctx context.Context, q relayQuerier, tenantID, domainID, uploadID uuid.UUID, lock string) (storedBlobUpload, bool, error) {
	query := `SELECT create_retry_id,subscription_id,publisher_member_id,relay_blob_id,byte_count,committed_offset,state,created_at_milliseconds,updated_at_milliseconds FROM relay_blob_uploads WHERE tenant_id=$1 AND domain_id=$2 AND upload_id=$3`
	if lock != "" {
		query += " " + lock
	}
	var result storedBlobUpload
	result.status.UploadID = uploadID
	err := q.QueryRow(ctx, query, tenantID, domainID, uploadID).Scan(&result.createRetryID, &result.subscriptionID, &result.publisherMemberID, &result.status.RelayBlobID, &result.status.ByteCount, &result.status.CommittedOffset, &result.state, &result.status.CreatedAtMilliseconds, &result.status.UpdatedAtMilliseconds)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedBlobUpload{}, false, nil
	}
	if err != nil {
		return storedBlobUpload{}, false, fmt.Errorf("load blob upload: %w", err)
	}
	result.status.Finalized = result.state == "finalized"
	return result, true, nil
}

func loadBlobUploadByRetry(ctx context.Context, q relayQuerier, tenantID, domainID, retryID uuid.UUID, lock string) (storedBlobUpload, bool, error) {
	var uploadID uuid.UUID
	query := `SELECT upload_id FROM relay_blob_uploads WHERE tenant_id=$1 AND domain_id=$2 AND create_retry_id=$3`
	if lock != "" {
		query += " " + lock
	}
	err := q.QueryRow(ctx, query, tenantID, domainID, retryID).Scan(&uploadID)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedBlobUpload{}, false, nil
	}
	if err != nil {
		return storedBlobUpload{}, false, err
	}
	return loadBlobUpload(ctx, q, tenantID, domainID, uploadID, "")
}
