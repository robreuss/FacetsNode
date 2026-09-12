package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

// One relay database and its backing blob filesystem form one capacity pool.
// All service instances using that pool must use this database (as they already
// must for upload custody). The transaction-scoped lock coordinates admissions
// across processes, accounts and Spaces, not merely one in-memory server.
const relayCapacityPoolLock int64 = 0x46616353796e6343

// SetSharedCapacityProvider is startup configuration, before serving requests.
// Probe failure is handled per write, allowing reads and cleanup to continue.
func (s *RelayStore) SetSharedCapacityProvider(provider storagecapacity.Provider) error {
	if provider == nil {
		return storagecapacity.ErrUnavailable
	}
	s.capacityProvider = provider
	return nil
}

func (s *RelayStore) admitSharedCapacity(ctx context.Context, tx pgx.Tx, additional int64) error {
	if s.capacityProvider == nil {
		return nil
	} // Other bounded service/test stores.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, relayCapacityPoolLock); err != nil {
		return fmt.Errorf("lock storage pool: %w", err)
	}
	// Active upload facts are the durable reservation ledger. A transaction
	// either changes these facts and commits, or retains the old reservation.
	// SUM uses numeric arithmetic; conversion overflow fails closed. Do not
	// drop expired-by-clock rows until cleanup durably marks them expired.
	var outstanding int64
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(SUM(2::numeric*u.byte_count - u.committed_offset + $1::bigint
		    + $2::bigint*(SELECT count(*) FROM relay_blob_upload_chunks c
		       WHERE c.tenant_id=u.tenant_id AND c.domain_id=u.domain_id AND c.upload_id=u.upload_id)),0)::bigint
		FROM relay_blob_uploads u WHERE u.state='active'
	`, storagecapacity.UploadMetadataAllowance, storagecapacity.ChunkMetadataAllowance).Scan(&outstanding)
	if err != nil {
		return fmt.Errorf("read storage reservations: %w", storagecapacity.ErrUnavailable)
	}
	snapshot, err := s.capacityProvider.Snapshot(ctx)
	if err != nil {
		return err
	}
	return storagecapacity.Check(snapshot, outstanding, additional)
}
