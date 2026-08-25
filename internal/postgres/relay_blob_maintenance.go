package postgres

import (
	"context"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func (s *RelayStore) ExpireBlobUploads(ctx context.Context, nowMilliseconds, graceMilliseconds int64) ([]relay.BlobUploadExpiry, error) {
	if ctx == nil || s == nil || s.pool == nil ||
		!validBlobMaintenanceTime(nowMilliseconds, graceMilliseconds) {
		return nil, serviceauthority.ErrInvalid
	}
	tenants, err := s.ExpiredBlobUploadTenantCandidates(ctx, nowMilliseconds)
	if err != nil {
		return nil, err
	}
	var expired []relay.BlobUploadExpiry
	for _, tenantID := range tenants {
		remaining := relay.MaximumBlobUploadExpiryBatchSize - len(expired)
		if remaining == 0 {
			break
		}
		items, err := s.ExpireBlobUploadsForTenant(
			ctx,
			tenantID,
			nowMilliseconds,
			graceMilliseconds,
			remaining,
		)
		expired = append(expired, items...)
		if err != nil {
			return expired, err
		}
	}
	return expired, nil
}

// ExpiredBlobUploadTenantCandidates discovers mutation scopes without changing
// state. Device Sync uses this boundary to obtain scope authority before any
// upload-expiry mutation is attempted.
func (s *RelayStore) ExpiredBlobUploadTenantCandidates(
	ctx context.Context,
	nowMilliseconds int64,
) ([]uuid.UUID, error) {
	if ctx == nil || s == nil || s.pool == nil || nowMilliseconds < 0 {
		return nil, serviceauthority.ErrInvalid
	}
	// Return one row for every candidate tenant. The caller bounds successful
	// expiries, while an ordered fixed prefix here would let fenced tenants hide
	// every writable tenant that follows them indefinitely.
	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id
		FROM relay_blob_uploads
		WHERE state='active' AND expires_at_milliseconds <= $1
		GROUP BY tenant_id
		ORDER BY MIN(expires_at_milliseconds), tenant_id
	`, nowMilliseconds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []uuid.UUID
	for rows.Next() {
		var tenantID uuid.UUID
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		if tenantID == uuid.Nil {
			return nil, serviceauthority.ErrInvalid
		}
		candidates = append(candidates, tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return candidates, nil
}

// ExpireBlobUploadsForTenant mutates only one tenant. Device Sync callers must
// hold that principal's in-process lease and durable scope fence for the full
// call; Shared Spaces may continue to use the aggregate maintenance method.
func (s *RelayStore) ExpireBlobUploadsForTenant(
	ctx context.Context,
	tenantID uuid.UUID,
	nowMilliseconds, graceMilliseconds int64,
	limit int,
) ([]relay.BlobUploadExpiry, error) {
	if ctx == nil || s == nil || s.pool == nil || tenantID == uuid.Nil ||
		!validBlobMaintenanceTime(nowMilliseconds, graceMilliseconds) ||
		limit <= 0 || limit > relay.MaximumBlobUploadExpiryBatchSize {
		return nil, serviceauthority.ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id,domain_id,upload_id
		FROM relay_blob_uploads
		WHERE tenant_id=$1 AND state='active' AND expires_at_milliseconds <= $2
		ORDER BY expires_at_milliseconds, domain_id, upload_id
		LIMIT $3
	`, tenantID, nowMilliseconds, limit)
	if err != nil {
		return nil, err
	}
	var candidates []relay.BlobUploadExpiry
	for rows.Next() {
		var item relay.BlobUploadExpiry
		if err := rows.Scan(
			&item.Scope.TenantID,
			&item.Scope.DomainID,
			&item.UploadID,
		); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var expired []relay.BlobUploadExpiry
	for _, item := range candidates {
		tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return expired, err
		}
		if _, err = loadRelayTenant(ctx, tx, item.Scope.TenantID, "FOR UPDATE"); err == nil {
			_, _, _, _, _, _, err = loadRelayDomain(ctx, tx, item.Scope.TenantID, item.Scope.DomainID, "FOR UPDATE")
		}
		var byteCount int64
		if err == nil {
			err = tx.QueryRow(ctx, `SELECT byte_count FROM relay_blob_uploads WHERE tenant_id=$1 AND domain_id=$2 AND upload_id=$3 AND state='active' AND expires_at_milliseconds <= $4 FOR UPDATE`, item.Scope.TenantID, item.Scope.DomainID, item.UploadID, nowMilliseconds).Scan(&byteCount)
		}
		if err == pgx.ErrNoRows {
			_ = tx.Rollback(ctx)
			continue
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE relay_domains SET reserved_blob_count=reserved_blob_count-1,reserved_blob_byte_count=reserved_blob_byte_count-$3 WHERE tenant_id=$1 AND domain_id=$2`, item.Scope.TenantID, item.Scope.DomainID, byteCount)
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE relay_tenants SET reserved_blob_count=reserved_blob_count-1,reserved_blob_byte_count=reserved_blob_byte_count-$2 WHERE tenant_id=$1`, item.Scope.TenantID, byteCount)
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE relay_blob_uploads SET state='expired',updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND upload_id=$3`, item.Scope.TenantID, item.Scope.DomainID, item.UploadID)
		}
		eligible := nowMilliseconds + graceMilliseconds
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO relay_blob_upload_deletions VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id,domain_id,upload_id) DO UPDATE SET eligible_at_milliseconds=EXCLUDED.eligible_at_milliseconds`, item.Scope.TenantID, item.Scope.DomainID, item.UploadID, eligible)
		}
		if err == nil {
			err = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if err != nil {
			return expired, fmt.Errorf("expire blob upload: %w", err)
		}
		expired = append(expired, item)
	}
	return expired, nil
}

func validBlobMaintenanceTime(nowMilliseconds, graceMilliseconds int64) bool {
	return nowMilliseconds >= 0 && graceMilliseconds >= 0 &&
		graceMilliseconds <= math.MaxInt64-nowMilliseconds
}

func (s *RelayStore) DeleteBlobIfUnauthorized(ctx context.Context, candidate relay.BlobContentCandidate, nowMilliseconds, graceMilliseconds int64, remove func() error) (bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockBlobScopeForCleanup(ctx, tx, candidate.Scope); err != nil {
		return false, err
	}
	var authoritative bool
	var collectedAt *int64
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM relay_blobs WHERE tenant_id=$1 AND domain_id=$2 AND blob_id=$3),(SELECT collected_at_milliseconds FROM relay_collected_blob_deletions WHERE tenant_id=$1 AND domain_id=$2 AND blob_id=$3)`, candidate.Scope.TenantID, candidate.Scope.DomainID, candidate.BlobID).Scan(&authoritative, &collectedAt)
	if err != nil {
		return false, err
	}
	if authoritative {
		return false, nil
	}
	eligible := candidate.ModifiedMilliseconds <= nowMilliseconds-graceMilliseconds
	if collectedAt != nil {
		eligible = *collectedAt <= nowMilliseconds-graceMilliseconds
	}
	if !eligible {
		return false, nil
	}
	if remove == nil {
		return false, fmt.Errorf("blob cleanup callback is missing")
	}
	if err := remove(); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (s *RelayStore) DeleteBlobUploadIfUnauthorized(ctx context.Context, candidate relay.BlobUploadContentCandidate, nowMilliseconds, graceMilliseconds int64, remove func() error) (bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockBlobScopeForCleanup(ctx, tx, candidate.Scope); err != nil {
		return false, err
	}
	var state *string
	var eligibleAt *int64
	err = tx.QueryRow(ctx, `SELECT (SELECT state FROM relay_blob_uploads WHERE tenant_id=$1 AND domain_id=$2 AND upload_id=$3),(SELECT eligible_at_milliseconds FROM relay_blob_upload_deletions WHERE tenant_id=$1 AND domain_id=$2 AND upload_id=$3)`, candidate.Scope.TenantID, candidate.Scope.DomainID, candidate.UploadID).Scan(&state, &eligibleAt)
	if err != nil {
		return false, err
	}
	if state != nil && *state == "active" {
		return false, nil
	}
	eligible := candidate.ModifiedMilliseconds <= nowMilliseconds-graceMilliseconds
	if eligibleAt != nil {
		eligible = *eligibleAt <= nowMilliseconds
	}
	if !eligible {
		return false, nil
	}
	if remove == nil {
		return false, fmt.Errorf("blob upload cleanup callback is missing")
	}
	if err := remove(); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func lockBlobScopeForCleanup(ctx context.Context, tx pgx.Tx, scope relay.BlobScope) error {
	var identifier string
	if err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM relay_tenants WHERE tenant_id=$1 FOR UPDATE`, scope.TenantID).Scan(&identifier); err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT domain_id::text FROM relay_domains WHERE tenant_id=$1 AND domain_id=$2 FOR UPDATE`, scope.TenantID, scope.DomainID).Scan(&identifier); err != nil && err != pgx.ErrNoRows {
		return err
	}
	return nil
}
